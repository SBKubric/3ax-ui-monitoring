// Package main is mon-client's entry point. It stays thin (spec §8:
// "cmd/mon-client/main.go — флаги, запуск"): main.go only wires
// os.Args/os.Stdout/os.Stderr into run, and every actual decision lives
// here in cli.go as plain functions that take their I/O as parameters, so
// a test can drive a full invocation without forking a real process.
package main

import (
	"context"
	"errors"
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
	"github.com/SBKubric/3ax-ui-monitoring/internal/version"
)

// httpClientForTests, when non-nil, replaces the plain *http.Client `run`
// otherwise builds for internal/client/api.New. Production never touches
// it; this package's own tests set it to a client trusting a
// servertest.Stub's self-signed certificate, so `run` can be driven all
// the way through registration against a stub without either a real
// mon-server or any flag/CA-file plumbing of its own (issue #16's brief:
// "keep it simple").
var httpClientForTests *http.Client

// beforeLoopForTests, when non-nil, is called with the run's cancel
// function after registration and just before the probe loop starts.
// Production never touches it; this package's own tests use it to stop a
// run that would otherwise only end on SIGINT/SIGTERM, so a CLI test still
// asserts on everything `run` does without waiting out a probe interval.
var beforeLoopForTests func(cancel context.CancelFunc)

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
	needsRegistration := false
	switch {
	case err == nil:
		logger.Info(fmt.Sprintf("state loaded (mon-client %s)", f.MonClientID))
	case errors.Is(err, state.ErrNoState):
		logger.Info("no state, registration required")
		needsRegistration = true
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
		needsRegistration = true
	}

	// Spec §6/§9: the loop runs until the box is stopped, so everything
	// below hangs off one context a SIGINT or SIGTERM cancels — including
	// the registration wait, which is otherwise the longest thing a
	// mon-client can be sitting in.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	hc := httpClientForTests
	if hc == nil {
		hc = &http.Client{}
	}

	if needsRegistration {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = ""
		}
		f, err = register.Run(ctx, register.Deps{
			API:      api.New(serverURL, hc),
			State:    dir,
			Log:      logger,
			Hostname: hostname,
			Version:  version.Version(),
			PublicIP: register.PublicIPFromDial(serverURL),
		})
		if err != nil {
			fmt.Fprintf(stderr, "mon-client: register: %v\n", err)
			return 1
		}
	}

	logger.Info(fmt.Sprintf("registered as %s", f.MonClientID))

	buffer, err := openBuffer(dir, logger)
	if err != nil {
		fmt.Fprintf(stderr, "mon-client: %v\n", err)
		return 1
	}

	client := api.New(serverURL, hc)
	client.Token = f.Token

	// The xray child is optional: spec §1 has mon-client probe AWG-targets
	// in-process, so a box with no xray binary installed is a working
	// mon-client for those targets. A missing binary is therefore a warning
	// and a nil child (the applier then refuses any document carrying
	// xray-targets, with that refusal as configError), not a failed start.
	child := openXray(*xrayBin, logger)
	applier := app.NewRevisionApplier(app.ApplierDeps{
		XrayProber: &probe.Prober{Logger: logger},
		AWGProber:  &awg.Prober{Log: logger},
		Xray:       child,
		Dir:        dir,
		File:       f,
		Log:        logger,
	})
	// Spec §9/§6: whatever ends the run — a signal, a 401, a 403 — must not
	// leave an xray child behind holding the socks ports.
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), xrayStopTimeout)
		defer stopCancel()
		if err := applier.Stop(stopCtx); err != nil {
			logger.Warn("xray not stopped cleanly", "error", err)
		}
	}()

	loop := app.NewLoop(app.Deps{
		API:         client,
		State:       dir,
		File:        f,
		Buffer:      buffer,
		Runner:      probe.NewRunner(logger),
		Applier:     applier,
		Log:         logger,
		Version:     version.Version(),
		XrayVersion: xrayVersion(ctx, child, logger),
		StartedAt:   time.Now(),
	})

	if beforeLoopForTests != nil {
		beforeLoopForTests(cancel)
	}
	if err := loop.Run(ctx); err != nil {
		// Spec §6's 401/403 branches are step 9's; until then, saying
		// exactly why mon-client stopped is the whole of the handling.
		fmt.Fprintf(stderr, "mon-client: %v\n", err)
		return 1
	}
	return 0
}

// openBuffer opens cycles.json, recovering from a file that cannot be
// decoded. heartbeat.OpenBuffer refuses such a file on purpose (starting
// over would reuse cycle seqs mon-server has already acknowledged), but
// refusing to start a mon-client over a corrupt statistics buffer is the
// worse trade: the operator is told, the file is moved out of the way, and
// the box goes back to probing.
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

// xrayStopTimeout is how long the shutdown path waits for the xray child
// to exit on SIGTERM before killing it (xray.Process.Stop escalates when
// the context ends). A child that has not gone in five seconds is stuck,
// and mon-client must still exit.
const xrayStopTimeout = 5 * time.Second

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
