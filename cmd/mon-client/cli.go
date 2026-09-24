// Package main is mon-client's entry point. It stays thin (spec §8:
// "cmd/mon-client/main.go — флаги, запуск"): main.go only wires
// os.Args/os.Stdout/os.Stderr into run, and every actual decision lives
// here in cli.go as plain functions that take their I/O as parameters, so
// a test can drive a full invocation without forking a real process.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/app"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/awg"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/register"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/version"
)

// hooks are this package's test seams, threaded through runCtx as a
// parameter rather than kept in package-level variables: a CLI test that
// mutated globals could not run alongside another one, and `run` is the
// only thing in mon-client that has no injection of its own.
//
// Production passes the zero value, which means "no hooks": a plain
// http.Client, the real clock, real timers, and nothing between
// registration and the probe loop.
type hooks struct {
	// HTTP replaces the *http.Client every api.Client is built over.
	// Tests set it to a client trusting a servertest.Stub's self-signed
	// certificate, so `run` goes through a full registration against a
	// stub without either a real mon-server or any CA-file flag.
	HTTP *http.Client
	// Clock and Sleep are the supervisor's and registration's time seams
	// (see app.SupervisorDeps). Tests inject an instant Sleep so a CLI
	// test does not wait out registration's 10-second poll cadence.
	Clock clock.Clock
	Sleep func(ctx context.Context, d time.Duration) error
	// BeforeLoop is called with the run's cancel function each time a loop
	// has been built and is about to run. Tests use it to stop a run that
	// would otherwise only end on SIGINT/SIGTERM.
	BeforeLoop func(cancel context.CancelFunc)
}

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
	return runCtx(context.Background(), args, stdout, stderr, hooks{})
}

// runCtx is run with its context and test seams supplied — the form this
// package's own tests drive, so they can cancel a run and hand it a stub's
// HTTP client without touching any global.
func runCtx(ctx context.Context, args []string, stdout, stderr io.Writer, h hooks) int {
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
		return runRun(ctx, args[1:], stdout, stderr, h)
	case strings.HasPrefix(cmd, "-"):
		// spec: "run" is the default command when args start with flags —
		// `mon-client --server ...` is shorthand for `mon-client run
		// --server ...`, since run is the only thing mon-client normally
		// does.
		return runRun(ctx, args, stdout, stderr, h)
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

// runRun parses run's flags and hands the box to the supervisor, which is
// mon-client's whole life cycle: register if needed, probe and heartbeat,
// re-register on a 401, wait out a 403 (spec §6). Everything this function
// still owns is process-level: flags, the logger, the state directory, the
// signal handling, and how a loop is built out of this box's xray binary.
func runRun(ctx context.Context, args []string, stdout, stderr io.Writer, h hooks) int {
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

	// Spec §6/§9: the run lasts until the box is stopped, so everything
	// below hangs off one context a SIGINT or SIGTERM cancels — including
	// the registration wait, which is otherwise the longest thing a
	// mon-client can be sitting in.
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	clk := h.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}

	if err := app.RunSupervisor(sigCtx, app.SupervisorDeps{
		ServerURL: serverURL,
		HTTP:      h.HTTP,
		Dir:       dir,
		Clock:     clk,
		Sleep:     h.Sleep,
		Log:       logger,
		Version:   version.Version(),
		Hostname:  hostname,
		PublicIP:  register.PublicIPFromDial(serverURL),
		NewLoop:   newLoop(sigCtx, cancel, dir, *xrayBin, logger, clk, h),
	}); err != nil {
		fmt.Fprintf(stderr, "mon-client: %v\n", err)
		return 1
	}
	return 0
}

// newLoop is the production app.LoopFactory: everything a running identity
// needs, rebuilt from scratch each time the supervisor starts one.
//
// Rebuilding rather than reusing is the point. A loop that comes back
// after a 401 belongs to a different mon-client with a different token,
// and one that comes back after a 403 may have been suspended for hours —
// in both cases a fresh cycles buffer handle, a fresh applier and a fresh
// xray child are cheaper to reason about than any attempt to carry state
// across the gap.
func newLoop(ctx context.Context, cancel context.CancelFunc, dir *state.Dir, xrayBin string, logger *slog.Logger, clk clock.Clock, h hooks) app.LoopFactory {
	startedAt := clk.Now()
	return func(f *state.File, client *api.Client) (*app.Loop, func(context.Context) error, error) {
		buffer, err := openBuffer(dir, logger)
		if err != nil {
			return nil, nil, err
		}

		// The xray child is optional: spec §1 has mon-client probe
		// AWG-targets in-process, so a box with no xray binary installed
		// is a working mon-client for those targets. A missing binary is
		// therefore a warning and a nil child (the applier then refuses
		// any document carrying xray-targets, with that refusal as
		// configError), not a failed start.
		child := openXray(xrayBin, logger)
		applier := app.NewRevisionApplier(app.ApplierDeps{
			XrayProber: &probe.Prober{Logger: logger},
			AWGProber:  &awg.Prober{Log: logger},
			Xray:       child,
			Dir:        dir,
			File:       f,
			Log:        logger,
		})

		loop := app.NewLoop(app.Deps{
			API:         client,
			State:       dir,
			File:        f,
			Buffer:      buffer,
			Runner:      probe.NewRunner(logger),
			Applier:     applier,
			Clock:       clk,
			Sleep:       h.Sleep,
			Log:         logger,
			Version:     version.Version(),
			XrayVersion: xrayVersion(ctx, child, logger),
			StartedAt:   startedAt,
		})

		if h.BeforeLoop != nil {
			h.BeforeLoop(cancel)
		}
		// Spec §9/§6: whatever ends the run — a signal, a 401, a 403 —
		// must not leave an xray child behind holding the socks ports, and
		// the applier is what started it.
		return loop, applier.Stop, nil
	}
}

// openBuffer opens cycles.json, recovering from a file that cannot be
// decoded. heartbeat.OpenBuffer refuses such a file on purpose (starting
// over would reuse cycle seqs mon-server has already acknowledged), but
// refusing to start a mon-client over a corrupt statistics buffer is the
// worse trade: the operator is told, the file is moved out of the way, and
// the box goes back to probing. The seq counter does not restart at 1:
// app.NewLoop continues it after the last ackSeq kept in state.json
// (decision #51 §1).
func openBuffer(dir *state.Dir, logger *slog.Logger) (*heartbeat.Buffer, error) {
	path := dir.Path("cycles.json")
	buf, err := heartbeat.OpenBuffer(path)
	if err == nil {
		return buf, nil
	}
	logger.Warn("cycles buffer unreadable, starting a fresh one", "error", err)
	if rmErr := os.Remove(path); rmErr != nil {
		return nil, rmErr
	}
	return heartbeat.OpenBuffer(path)
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

// openXray returns the xray child process, or nil when --xray-bin does not
// point at an executable. See the call site for why that is not fatal.
func openXray(bin string, logger *slog.Logger) *xray.Process {
	if _, err := os.Stat(bin); err != nil {
		logger.Warn("no xray binary, xray-targets cannot be probed", "path", bin, "error", err)
		return nil
	}
	return xray.New(bin, logger)
}

// xrayVersion reads the child binary's version once, at start, for the
// heartbeat's client.xrayVersion (protocol §5.3). Once, because the binary
// does not change under a running mon-client and asking it per heartbeat
// would fork a process a minute for a string that never moves.
func xrayVersion(ctx context.Context, child *xray.Process, logger *slog.Logger) func() string {
	if child == nil {
		return nil
	}
	vctx, cancel := context.WithTimeout(ctx, xrayVersionTimeout)
	defer cancel()
	v, err := child.Version(vctx)
	if err != nil {
		logger.Warn("xray version unavailable", "error", err)
	}
	return func() string { return v }
}

// xrayVersionTimeout bounds that one `xray version` call: a binary that
// does not answer in a second is not going to be asked again.
const xrayVersionTimeout = time.Second
