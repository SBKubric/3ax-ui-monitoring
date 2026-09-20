// Package main is mon-client's entry point. It stays thin (spec §8:
// "cmd/mon-client/main.go — флаги, запуск"): main.go only wires
// os.Args/os.Stdout/os.Stderr into run, and every actual decision lives
// here in cli.go as plain functions that take their I/O as parameters, so
// a test can drive a full invocation without forking a real process.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/version"
)

// envServerURL is spec §2's ENV alternative to --server.
const envServerURL = "MON_SERVER_URL"

// defaultStateDir, defaultXrayBin and defaultLogLevel are spec §2's
// defaults for the three optional flags.
const (
	defaultStateDir = "/var/lib/mon-client"
	defaultXrayBin  = "/usr/local/bin/xray"
	defaultLogLevel = "info"
)

// run is the whole CLI, parameterised over its arguments and I/O exactly
// like cmd/mon-server's own run, so tests exercise it without touching the
// real os.Args. It returns the process exit code; main's only job is to
// pass that to os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage())
		return 2
	}

	cmd := args[0]
	switch {
	case cmd == "version":
		fmt.Fprintf(stdout, "mon-client %s\n", version.Version())
		return 0
	case cmd == "-h" || cmd == "--help" || cmd == "help":
		fmt.Fprintln(stdout, usage())
		return 0
	case cmd == "run":
		return runRun(args[1:], stdout, stderr)
	case strings.HasPrefix(cmd, "-"):
		// spec: "run" is the default command when args start with flags —
		// `mon-client --server ...` is shorthand for `mon-client run
		// --server ...`, since run is the only thing mon-client normally
		// does.
		return runRun(args, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "mon-client: unknown command %q\n\n%s\n", cmd, usage())
		return 2
	}
}

func usage() string {
	return `Usage:
  mon-client [run] --server <url> [--state-dir dir] [--xray-bin path] [--log-level level]
                                           start the service (--server may also
                                           come from ` + envServerURL + `)
  mon-client version                      print the build version

--state-dir defaults to ` + defaultStateDir + `
--xray-bin defaults to ` + defaultXrayBin + `
--log-level is one of debug, info, warn, error (default ` + defaultLogLevel + `)`
}

// runRun parses run's flags, opens the state directory, and reports
// whether this box is already registered (issue #15: the loop itself
// arrives in step 7 — for now, `run` just proves the state file round-trips
// end to end and exits).
func runRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "mon-server URL, e.g. https://203.0.113.10:443 (or "+envServerURL+")")
	stateDir := fs.String("state-dir", defaultStateDir, "state directory")
	xrayBin := fs.String("xray-bin", defaultXrayBin, "path to the xray binary")
	logLevel := fs.String("log-level", defaultLogLevel, "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "mon-client: unexpected argument %q\n\n%s\n", fs.Arg(0), usage())
		return 2
	}
	_ = xrayBin // wired into internal/client/xray from step 4 on

	serverURL := *server
	if serverURL == "" {
		serverURL = os.Getenv(envServerURL)
	}
	if serverURL == "" {
		// Spec §2: "единственный обязательный параметр" — without it there
		// is nothing to register with, so this is a usage error (exit 2),
		// not a runtime one.
		fmt.Fprintf(stderr, "mon-client: --server or %s is required\n\n%s\n", envServerURL, usage())
		return 2
	}

	level, ok := parseLogLevel(*logLevel)
	if !ok {
		fmt.Fprintf(stderr, "mon-client: invalid --log-level %q\n\n%s\n", *logLevel, usage())
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stdout, &slog.HandlerOptions{Level: level}))

	dir, err := state.Open(*stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "mon-client: %v\n", err)
		return 1
	}

	f, err := dir.Load()
	switch {
	case err == nil:
		logger.Info(fmt.Sprintf("state loaded (mon-client %s)", f.MonClientID))
	case errors.Is(err, state.ErrNoState):
		logger.Info("no state, registration required")
	default:
		// A corrupt state file (spec §2: "Пропал или 401 — стереть и
		// регистрироваться заново" — the same recovery applies to a state
		// file that is present but unreadable) is treated the same as no
		// state at all, once the operator has been told why.
		logger.Warn("state file unreadable, clearing it", "error", err)
		if clearErr := dir.Clear(); clearErr != nil {
			fmt.Fprintf(stderr, "mon-client: %v\n", clearErr)
			return 1
		}
		logger.Info("no state, registration required")
	}

	_ = serverURL // wired into internal/client/register from step 2 on

	// The registration/probe/heartbeat loop arrives in step 7
	// (internal/client/app.Loop); step 1 only proves flags, state and
	// logging work end to end.
	return 0
}

// parseLogLevel maps --log-level's four accepted spellings (issue #15) onto
// slog's levels; anything else is rejected rather than silently defaulted,
// so a typo in an operator's systemd unit fails loudly instead of quietly
// running at the wrong verbosity.
func parseLogLevel(s string) (slog.Level, bool) {
	switch s {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return 0, false
	}
}
