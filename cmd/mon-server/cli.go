// Package main is mon-server's entry point. It stays thin (spec §11:
// "cmd/mon-server/main.go — CLI: run, admin set, version"): main.go only
// wires os.Args/os.Stdin/os.Stdout/os.Stderr into run, and every actual
// decision lives here in cli.go, as plain functions that take their I/O as
// parameters — so a test can drive `admin set`'s interactive password
// prompt or capture `version`'s output without forking a real process.
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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/SBKubric/3ax-ui-monitoring/internal/app"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// defaultConfigPath is the bootstrap file spec §2 names; overridable with
// -config for tests and non-standard installs.
const defaultConfigPath = "/etc/mon-server/config.json"

// envAdminPassword lets `admin set` run non-interactively (e.g. from a
// provisioning script or this package's own tests) instead of prompting a
// terminal that may not exist.
const envAdminPassword = "MON_ADMIN_PASSWORD"

// run is the whole CLI, parameterised over its arguments and I/O so tests
// exercise it exactly like a real invocation without touching the real
// os.Args or a real terminal. It returns the process exit code; main's only
// job is to pass that to os.Exit.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runCtx(context.Background(), args, stdin, stdout, stderr, nil)
}

// runCtx is run's real body: ctx and onListen exist purely so this
// package's own tests can drive `run` (specifically its "run" subcommand)
// deterministically — cancelling ctx directly instead of racing a real
// OS signal against a freshly-picked port, and learning the bound address
// via onListen instead of having to know it in advance. run always passes
// context.Background() and a nil onListen; only the "run" subcommand (via
// runRun) makes use of either.
func runCtx(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, onListen func(addr string)) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return 2
	}

	switch args[0] {
	case "run":
		return runRun(ctx, args[1:], stderr, onListen)
	case "admin":
		return runAdmin(args[1:], stdin, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mon-server %s\n", config.Version())
		return 0
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage())
		return 0
	default:
		fmt.Fprintf(stderr, "mon-server: unknown command %q\n\n%s\n", args[0], usage())
		return 2
	}
}

func usage() string {
	return `Usage:
  mon-server run [-config path]           start the service
  mon-server admin set <user> [-config path]
                                           set the admin login and password
                                           (prompts twice on a terminal; or
                                           set ` + envAdminPassword + ` to run
                                           non-interactively)
  mon-server version                      print the build version

-config defaults to ` + defaultConfigPath
}

// configFlagSet reports whether -config was actually given on the command
// line, as opposed to fs's "config" flag merely holding its default value —
// config.Load needs to know the difference so a missing file is only ever
// tolerated when nobody explicitly asked for that file.
func configFlagSet(fs *flag.FlagSet) bool {
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			explicit = true
		}
	})
	return explicit
}

// runRun loads and validates the bootstrap config, opens the store, wires up
// the App (internal/app: TLS, the gin engine, the HTTPS listener) and runs
// it until SIGINT, SIGTERM, or ctx itself is cancelled (parent asks it to
// stop; production always passes context.Background(), so in practice this
// is always a signal — cli_test.go's own tests are what actually cancel a
// live ctx directly, to avoid racing a real signal against a freshly-picked
// port). Validation happens before anything with a side effect (opening the
// store, building TLS, binding the listener), so a bad config file fails
// fast and loud instead of a process that appears to hang or half-starts.
//
// Start, Wait and Shutdown are called separately here rather than via
// App.Run, specifically so stop() can run between Wait and Shutdown:
// signal.NotifyContext's own doc comment recommends calling stop as soon as
// the first signal has been handled, so that a second SIGINT/SIGTERM falls
// through to Go's default handling (an immediate exit) instead of being
// silently absorbed by a ctx that's already Done while a slow graceful
// shutdown is still in progress.
func runRun(ctx context.Context, args []string, stderr io.Writer, onListen func(addr string)) int {
	const usage = "Usage: mon-server run [-config path]"

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "bootstrap config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "mon-server: unexpected argument %q\n\n%s\n", fs.Arg(0), usage)
		return 2
	}

	cfg, err := config.Load(*configPath, configFlagSet(fs))
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}

	dbPath := filepath.Join(cfg.DataDir, "mon-server.db")
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: open store: %v\n", err)
		return 1
	}

	a, err := app.New(app.Deps{
		Cfg:   cfg,
		Store: st,
		Clock: clock.Real{},
		// tg.NewFromSettings rereads tgToken/tgChatId from Settings on every
		// Send (spec §9.4), so an admin can fill in the Telegram tab or
		// change bots at runtime with no restart; NewHTTP(nil, "") is the
		// real Bot API client (step 9).
		Notifier: tg.NewFromSettings(st, tg.NewHTTP(nil, "")),
	})
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}

	// SIGINT (Ctrl-C, an operator running it in a foreground shell) and
	// SIGTERM (systemd stop, container shutdown) both mean "shut down
	// gracefully"; NotifyContext cancels sigCtx on either, or when ctx
	// itself is cancelled, instead of the process dying mid-request.
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	addr, err := a.Start()
	if err != nil {
		stop()
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}
	slog.Info("listening", "addr", addr, "tls", cfg.TLS.Mode)
	if onListen != nil {
		onListen(addr)
	}

	runErr := a.Wait(sigCtx)

	// See the doc comment above: stop relaying signals before the
	// (potentially slow) graceful shutdown, not after.
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), app.ShutdownGrace)
	defer cancel()
	if shutErr := a.Shutdown(shutdownCtx); shutErr != nil && runErr == nil {
		runErr = shutErr
	}
	slog.Info("shutdown complete")

	if runErr != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", runErr)
		return 1
	}
	return 0
}

// runAdmin implements `admin set <user>`. Flags are parsed before the
// username is read off fs.Arg(0) — not args[1] directly — so that
// `admin set -config /x alice` assigns -config to the flag set instead of
// silently becoming the username "-config"; a username still starting with
// "-" after that (e.g. a genuinely missing username followed by a flag) is
// rejected outright, and exactly one positional argument is required. Config
// is loaded and the store opened before the password prompt (see
// adminPassword) so a bad config or an unopenable store fails before the
// operator has typed a password at all.
func runAdmin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	const usage = "Usage: mon-server admin set <user> [-config path]"

	if len(args) < 1 || args[0] != "set" {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	fs := flag.NewFlagSet("admin set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "bootstrap config file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "mon-server: admin set wants exactly one username\n\n%s\n", usage)
		return 2
	}
	username := fs.Arg(0)
	if strings.HasPrefix(username, "-") {
		fmt.Fprintf(stderr, "mon-server: username %q looks like a flag\n\n%s\n", username, usage)
		return 2
	}

	cfg, err := config.Load(*configPath, configFlagSet(fs))
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}

	dbPath := filepath.Join(cfg.DataDir, "mon-server.db")
	st, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: open store: %v\n", err)
		return 1
	}

	password, err := adminPassword(stdin, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}

	if err := st.SetAdmin(username, password); err != nil {
		fmt.Fprintf(stderr, "mon-server: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "admin login set for %q\n", username)
	return 0
}

// adminPassword returns the password for `admin set`: MON_ADMIN_PASSWORD if
// set, else two matching, non-empty terminal reads. stdin/stdout/stderr are
// parameters (not os.Stdin etc.) purely for testability; the non-interactive
// env path is what lets a test exercise this without a real tty. A single
// bufio.Reader is created here and shared between both readPassword calls
// (see its doc comment for why: a fresh bufio.Reader per call buffers ahead
// past the first line's newline and swallows the second line too).
func adminPassword(stdin io.Reader, stdout, stderr io.Writer) (string, error) {
	if pw, ok := os.LookupEnv(envAdminPassword); ok {
		if pw == "" {
			return "", errors.New("MON_ADMIN_PASSWORD is set but empty")
		}
		return pw, nil
	}

	br := bufio.NewReader(stdin)

	first, err := readPassword(stdin, br, stdout, stderr, "Password: ")
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", errors.New("password must not be empty")
	}
	second, err := readPassword(stdin, br, stdout, stderr, "Confirm password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords did not match")
	}
	return first, nil
}

// readPassword prompts on stdout and reads one line without local echo when
// stdin is a real terminal (golang.org/x/term), falling back to a line read
// from br otherwise — e.g. under `go test`, where stdin is not a file
// descriptor term recognises. br must be the same *bufio.Reader across both
// calls in a single adminPassword invocation: a fresh bufio.Reader per call
// would read ahead into its own internal buffer on the first prompt,
// consuming the confirm line's bytes along with the password line's, so the
// second call would see EOF instead of the operator's second line — the
// piped-input case (`printf 'pw\npw\n' | mon-server admin set alice`) always
// failed "passwords did not match" for exactly this reason. stdin itself is
// still passed through, unbuffered, so the terminal-detection type
// assertion below keeps working on the real *os.File.
func readPassword(stdin io.Reader, br *bufio.Reader, stdout, stderr io.Writer, prompt string) (string, error) {
	fmt.Fprint(stdout, prompt)

	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(b), nil
	}

	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}
