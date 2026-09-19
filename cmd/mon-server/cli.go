// Package main is mon-server's entry point. It stays thin (spec §11:
// "cmd/mon-server/main.go — CLI: run, admin set, version"): main.go only
// wires os.Args/os.Stdin/os.Stdout/os.Stderr into run, and every actual
// decision lives here in cli.go, as plain functions that take their I/O as
// parameters — so a test can drive `admin set`'s interactive password
// prompt or capture `version`'s output without forking a real process.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/SBKubric/3ax-ui-monitoring/internal/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
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
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return 2
	}

	switch args[0] {
	case "run":
		return runRun(args[1:], stderr)
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

// runRun loads and validates the bootstrap config, opens the store, and then
// stops: the listener does not exist until step 2 (TLS) and internal/app
// (wiring) land. Returning a clear, named error here instead of silently
// exiting 0 is deliberate — anyone running `mon-server run` today gets an
// honest "not built yet" instead of a process that appears to hang.
func runRun(args []string, stderr io.Writer) int {
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
	if _, err := store.Open(dbPath); err != nil {
		fmt.Fprintf(stderr, "mon-server: open store: %v\n", err)
		return 1
	}

	fmt.Fprintln(stderr, "run: listener arrives in step 2")
	return 1
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
