// Command mon-server is the monitoring server of 3AX-UI: the registry of
// mon-clients, the state machine of their targets and the only writer to the
// panel's monitoring API (spec docs/spec/mon-server.md).
//
// It has three commands:
//
//	mon-server run [-config <path>] [-log-level <level>]
//	mon-server admin set <user> [-config <path>]
//	mon-server version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/SBKubric/3ax-ui-monitoring/internal/app"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// version is the build version, set at link time with
// -ldflags "-X main.version=<version>".
var version = "dev"

// Process exit codes: 0 success, 1 a failure while doing the work, 2 a command
// line the process does not understand.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// envAdminPassword lets `admin set` run without a terminal, which is how the
// Docker image and the e2e compose seed their administrator.
const envAdminPassword = "MON_ADMIN_PASSWORD"

const usage = `mon-server — monitoring server for 3AX-UI

Usage:
  mon-server run [-config <path>] [-log-level <level>]
        Run the service: one HTTPS listener serving /v1/* for mon-clients,
        /admin/* for the admin UI and /healthz.
  mon-server admin set <user> [-config <path>]
        Set the admin UI login and password. The password is asked twice on
        the terminal and stored as a bcrypt hash. A repeat call replaces both
        the login and the password. When MON_ADMIN_PASSWORD is set the value
        is taken from it and nothing is asked, which is how a container seeds
        its administrator.
  mon-server version
        Print the version.

Flags:
  -config <path>      bootstrap configuration file (default %s)
  -log-level <level>  debug, info, warn or error (default info)

The bootstrap settings may also come from the environment: MON_LISTEN,
MON_PUBLIC_IP, MON_DATA_DIR, MON_TLS_MODE, MON_TLS_CERT, MON_TLS_KEY; the
environment wins over the file. Everything else is configured in the admin UI.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run dispatches one command line and returns the process exit code. main is
// the only caller in production; the tests drive it with their own streams.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "run":
		return serveCommand(args[1:], stderr)
	case "admin":
		return adminCommand(args[1:], stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version)
		return exitOK
	case "help", "-h", "-help", "--help":
		printUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "mon-server: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(w io.Writer) { fmt.Fprintf(w, usage, config.DefaultPath) }

// serveCommand implements `mon-server run`.
func serveCommand(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mon-server run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "mon-server run: unexpected argument %q\n\n", fs.Arg(0))
		printUsage(stderr)
		return exitUsage
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server run: %v\n\n", err)
		printUsage(stderr)
		return exitUsage
	}
	cfg, err := loadConfig(*configPath, stderr)
	if err != nil {
		return exitError
	}
	log := newLogger(stderr, level)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, cfg, log); err != nil {
		log.Error("mon-server stopped", "error", err)
		return exitError
	}
	return exitOK
}

// serve builds mon-server and runs it until ctx is cancelled, which happens
// on SIGINT or SIGTERM.
func serve(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	a, err := app.New(app.Options{Config: cfg, Version: version, Log: log})
	if err != nil {
		return err
	}
	defer func() {
		if err := a.Close(); err != nil {
			log.Error("closing mon-server", "error", err)
		}
	}()

	err = a.Run(ctx)
	log.Info("mon-server shutting down")
	return err
}

// adminCommand implements `mon-server admin set <user>`.
func adminCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mon-server admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }
	configPath := fs.String("config", config.DefaultPath, "bootstrap configuration file")
	words, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(words) != 2 || words[0] != "set" {
		fmt.Fprint(stderr, "mon-server: usage is `mon-server admin set <user>`\n\n")
		printUsage(stderr)
		return exitUsage
	}
	user := words[1]

	cfg, err := loadConfig(*configPath, stderr)
	if err != nil {
		return exitError
	}
	log := newLogger(stderr, slog.LevelWarn)
	st, err := store.Open(cfg.DBPath(), log)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return exitError
	}
	defer st.Close()

	password, ok := os.LookupEnv(envAdminPassword)
	if ok {
		// Non-interactive path, for a container or an installer that has no
		// terminal to prompt on. It is deliberately the only way to set the
		// password without typing it twice.
		if password == "" {
			fmt.Fprintf(stderr, "mon-server: %s is set but empty, nothing was changed\n", envAdminPassword)
			return exitError
		}
	} else {
		prompt := newPrompter(stdin, stderr)
		typed, err := prompt.password(fmt.Sprintf("Password for %s: ", user))
		if err != nil {
			fmt.Fprintf(stderr, "mon-server: %v\n", err)
			return exitError
		}
		again, err := prompt.password("Repeat password: ")
		if err != nil {
			fmt.Fprintf(stderr, "mon-server: %v\n", err)
			return exitError
		}
		if typed != again {
			fmt.Fprintln(stderr, "mon-server: the passwords do not match, nothing was changed")
			return exitError
		}
		password = typed
	}
	if err := st.SetAdmin(user, password); err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return exitError
	}
	fmt.Fprintf(stdout, "admin user %q updated in %s\n", user, cfg.DBPath())
	return exitOK
}

// loadConfig loads and validates the bootstrap configuration, reporting the
// failure on stderr in the shape the operator sees.
func loadConfig(path string, stderr io.Writer) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return config.Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "mon-server: invalid configuration: %v\n", err)
		return config.Config{}, err
	}
	return cfg, nil
}

// parseInterspersed parses fs allowing flags before, between and after the
// positional arguments, so that both `admin -config x set root` and
// `admin set root -config x` work. It returns the positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var words []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return words, nil
		}
		words = append(words, args[0])
		args = args[1:]
	}
}

// newLogger builds the structured logger the whole process shares.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// parseLevel maps the -log-level flag to a slog level.
func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q, want debug, info, warn or error", name)
	}
}

// prompter reads secrets from the terminal. golang.org/x/term is not among the
// module's dependencies, so echo is turned off with stty when the input is a
// terminal and stty is available; otherwise the prompt says that the password
// will be visible rather than pretending it is hidden.
type prompter struct {
	in  *bufio.Reader
	tty *os.File // nil unless the input is a terminal
	out io.Writer
}

// newPrompter prepares a prompter reading from in and prompting on out. The
// reader is shared by every prompt, so no input is lost between them.
func newPrompter(in io.Reader, out io.Writer) *prompter {
	p := &prompter{in: bufio.NewReader(in), out: out}
	if f, ok := in.(*os.File); ok && isTerminal(f) {
		p.tty = f
	}
	return p
}

// password writes prompt and reads one line, without echoing it when it can.
func (p *prompter) password(prompt string) (string, error) {
	hidden := false
	if p.tty != nil {
		if restore, ok := disableEcho(p.tty); ok {
			hidden = true
			defer restore()
		}
	}
	if p.tty != nil && !hidden {
		fmt.Fprint(p.out, strings.TrimSuffix(prompt, " ")+" (visible, stty is unavailable): ")
	} else {
		fmt.Fprint(p.out, prompt)
	}
	line, err := p.in.ReadString('\n')
	if hidden {
		// The terminal did not echo the Enter that ended the line.
		fmt.Fprintln(p.out)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	if line == "" && errors.Is(err, io.EOF) {
		return "", errors.New("read password: no input")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// isTerminal reports whether f is a character device, which is what a terminal
// looks like from here.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// disableEcho turns terminal echo off for tty and returns the function that
// turns it back on. It reports false when echo could not be turned off, and
// then changes nothing.
func disableEcho(tty *os.File) (restore func(), ok bool) {
	if err := stty(tty, "-echo"); err != nil {
		return func() {}, false
	}
	return func() { _ = stty(tty, "echo") }, true
}

// stty runs one stty command against tty.
func stty(tty *os.File, arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = tty
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
