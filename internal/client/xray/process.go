package xray

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// readyPoll is how often Start checks whether the child's socks inbounds
	// accept connections (spec §4 step 3: "дождаться готовности
	// socks-портов"). xray binds its inbounds within milliseconds of start,
	// so a 50 ms poll makes a restart between cycles imperceptible without
	// hammering the loopback.
	readyPoll = 50 * time.Millisecond

	// readyDialTimeout bounds one readiness dial. The target is loopback, so
	// anything that does not answer instantly is simply not bound yet.
	readyDialTimeout = 200 * time.Millisecond

	// stopGrace is how long a failed Start waits for the child it is
	// abandoning to die before killing it. A Start that could not reach
	// readiness must leave no xray behind: the caller will try again with a
	// new config and the old child would still hold the socks ports.
	stopGrace = 2 * time.Second

	// maxStderrLine caps one stderr line kept in the ring. xray can print a
	// whole HTML body when the Reality spider runs (research §2.4) and the
	// buffer must stay bounded.
	maxStderrLine = 4096
)

// Process is mon-client's child xray (spec §1: "дочерний xray (бинарь из
// официального образа, конфиг в файл, stderr в pipe)"). One Process serves
// every xray-target through the generated xray.json; applying a new config
// revision means Test then Restart between cycles (spec §4 step 3).
//
// All methods are safe for concurrent use: probes read the stderr ring while
// the apply path restarts the child.
type Process struct {
	bin string
	log *slog.Logger

	// ring is the stderr window every probe consults. It belongs to the
	// Process, not to one child: a restart must not lose the lines that
	// explain why the previous config was failing.
	ring *Ring

	mu  sync.Mutex
	cur *child
}

// child is one run of the binary. It exists so that Running() can be
// truthful: a goroutine waits on the process and closes done, so a child that
// died on its own (bad config, OOM) is never reported as running.
type child struct {
	cmd  *exec.Cmd
	done chan struct{}

	mu    sync.Mutex
	first string // first non-empty output line, for fail-fast errors
}

// New returns a Process for the xray binary at bin (--xray-bin, spec §2).
// Nothing is started until Start; logger may be nil, in which case
// slog.Default() is used.
func New(bin string, logger *slog.Logger) *Process {
	if logger == nil {
		logger = slog.Default()
	}
	return &Process{bin: bin, log: logger, ring: NewRing(RingLines)}
}

// Log returns the stderr ring buffer of the child (spec §5). Probes take a
// Snapshot of it and pass it to Diagnose.
func (p *Process) Log() *Ring { return p.ring }

// Diagnose explains a probe to target from this Process's stderr window.
// It is the adapter the probe package's Diagnoser interface expects; the
// matching itself is the pure Diagnose function.
func (p *Process) Diagnose(target Target, since, until time.Time) (Match, bool) {
	return Diagnose(p.ring.Snapshot(), target, since, until)
}

// Test runs `xray -test -c <cfgPath>`: the gate a generated config must pass
// before it is applied (spec §4 step 3). It never touches the running child —
// it is a separate short-lived process — so a config that fails validation
// leaves mon-client probing on the previous revision.
//
// The returned error's text is the first non-empty line xray printed, capped
// at 256 characters, because that text goes into the heartbeat as
// configError verbatim (spec §4 step 3: "первая строка ошибки, ≤ 256
// символов").
func (p *Process) Test(ctx context.Context, cfgPath string) error {
	out, err := p.output(ctx, "-test", "-c", cfgPath)
	if err == nil {
		return nil
	}
	line := errorLine(out)
	if line == "" {
		line = err.Error()
	}
	return errors.New(trimDetail(line))
}

// Version returns the child binary's version for the heartbeat's
// client.xrayVersion field (protocol §5.3). `xray version` prints "Xray
// 26.3.27 (Xray, Penetrates Everything.) …" (research §2.2), so the version
// number is what we keep — the constant word "Xray" would tell an operator
// nothing.
func (p *Process) Version(ctx context.Context) (string, error) {
	out, err := p.output(ctx, "version")
	if err != nil {
		line := errorLine(out)
		if line == "" {
			line = err.Error()
		}
		return "", errors.New(trimDetail(line))
	}
	fields := strings.Fields(firstNonEmptyLine(out))
	if len(fields) == 0 {
		return "", errors.New("xray version: empty output")
	}
	if len(fields) > 1 && strings.EqualFold(fields[0], "xray") {
		return fields[1], nil
	}
	return fields[0], nil
}

// output runs the binary with args and returns everything it printed on both
// streams. xray sends its log to stderr but prints `-test`'s verdict and
// `version` to stdout, so both are captured and searched.
func (p *Process) output(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Start runs `xray run -c <cfgPath>` with its output piped into the stderr
// ring, and returns once every port in readyPorts accepts a TCP connection on
// 127.0.0.1 — the socks inbounds of the generated config (spec §4 step 3).
// ctx bounds the wait only: the child outlives Start and is stopped by Stop.
//
// Start fails fast if the child exits before the ports come up (a config xray
// accepted at -test time but cannot run, a port already taken); the error
// then carries the first line the child printed. A Start that fails for any
// reason leaves no child behind.
func (p *Process) Start(ctx context.Context, cfgPath string, readyPorts []int) error {
	p.mu.Lock()
	if p.cur != nil && !exited(p.cur.done) {
		p.mu.Unlock()
		return errors.New("xray: already running")
	}
	cmd := exec.Command(p.bin, "run", "-c", cfgPath)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("xray: stderr pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		p.mu.Unlock()
		return fmt.Errorf("xray: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		p.mu.Unlock()
		return fmt.Errorf("xray: start %s: %w", p.bin, err)
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	p.cur = c
	p.mu.Unlock()

	// The readers must drain the pipes before Wait closes them, hence the
	// WaitGroup between them and the reaper goroutine.
	var readers sync.WaitGroup
	readers.Add(2)
	go p.read(c, stderr, &readers)
	go p.read(c, stdout, &readers)
	go func() {
		readers.Wait()
		_ = cmd.Wait()
		close(c.done)
	}()

	if err := p.waitReady(ctx, c, readyPorts); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), stopGrace)
		defer cancel()
		_ = p.Stop(stopCtx)
		return err
	}
	p.log.Info("xray started", "config", cfgPath, "ports", readyPorts)
	return nil
}

// read copies one of the child's streams into the ring, mirroring every line
// to the logger at debug level (spec §7: "debug добавляет stderr xray
// целиком").
func (p *Process) read(c *child, r io.ReadCloser, wg *sync.WaitGroup) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxStderrLine)
	for sc.Scan() {
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		p.ring.AppendText(text)
		c.noteFirst(text)
		p.log.Debug("xray", "line", text)
	}
	_ = r.Close()
}

// waitReady polls the socks ports until they all accept, the child dies, or
// ctx ends.
func (p *Process) waitReady(ctx context.Context, c *child, ports []int) error {
	for {
		if portsReady(ports) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("xray: ports %v not ready: %w", ports, ctx.Err())
		case <-c.done:
			if line := c.firstLine(); line != "" {
				return errors.New(trimDetail(line))
			}
			return errors.New("xray: child exited before its ports came up")
		case <-time.After(readyPoll):
		}
	}
}

// Stop terminates the child with SIGTERM and waits for it, escalating to
// SIGKILL when ctx ends (spec §4 step 3: "SIGTERM, ждать, старт"). It is
// idempotent and safe on a Process that was never started, so the shutdown
// path and the apply path can both call it without bookkeeping.
func (p *Process) Stop(ctx context.Context) error {
	p.mu.Lock()
	c := p.cur
	p.mu.Unlock()
	if c == nil || exited(c.done) {
		return nil
	}
	if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		// The process may have died between the check and the signal; that
		// is not an error, anything else is worth knowing about.
		p.log.Warn("xray: SIGTERM failed", "err", err)
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		p.log.Warn("xray: did not exit on SIGTERM, killing")
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	p.log.Info("xray stopped")
	return nil
}

// Restart stops the child and starts it on the new config, waiting for the
// socks ports again. This is the apply path between two probe cycles (spec §4
// step 3): the caller has already written xray.json and passed Test.
func (p *Process) Restart(ctx context.Context, cfgPath string, readyPorts []int) error {
	if err := p.Stop(ctx); err != nil {
		return err
	}
	return p.Start(ctx, cfgPath, readyPorts)
}

// Running reports whether a child is alive. It is driven by the goroutine
// that waits on the process, so a child that exited on its own reads as not
// running without anyone having to poll it.
func (p *Process) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cur != nil && !exited(p.cur.done)
}

// noteFirst remembers the first line worth reporting the child printed; Start
// uses it to explain an early exit. Noise (the version banner, the Info lines
// of config loading) is skipped, because that text ends up in the heartbeat
// as configError.
func (c *child) noteFirst(text string) {
	if noiseLine(text) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.first == "" {
		c.first = strings.TrimSpace(text)
	}
}

func (c *child) firstLine() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.first
}

// exited reports whether the child's done channel has been closed.
func exited(done chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// portsReady reports whether every port accepts a TCP connection on
// 127.0.0.1 — xray's socks inbounds listen on loopback only (spec §4 step 2).
func portsReady(ports []int) bool {
	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), readyDialTimeout)
		if err != nil {
			return false
		}
		_ = conn.Close()
	}
	return true
}

// errorLine picks the line of out that explains a failed run. Xray always
// opens with its version banner and the Info lines of config loading and puts
// the real message last ("Failed to start: main: failed to load config files
// … please add/set \"encryption\":\"none\"" — verified against
// ghcr.io/xtls/xray-core:latest), so the banner and every non-Error log line
// are skipped; if only noise was printed, the last line is better than
// nothing.
func errorLine(out string) string {
	last := ""
	for _, l := range strings.Split(out, "\n") {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}
		last = s
		if !noiseLine(s) {
			return s
		}
	}
	return last
}

// noiseLine reports whether a line of xray output is banner or routine log
// chatter rather than something an operator needs to see in configError.
func noiseLine(text string) bool {
	s := strings.TrimSpace(text)
	if s == "" {
		return true
	}
	if strings.HasPrefix(s, "Xray ") && strings.Contains(s, "(Xray,") {
		return true
	}
	if s == "A unified platform for anti-censorship." {
		return true
	}
	if m := logLevel.FindStringSubmatch(s); m != nil && !strings.EqualFold(m[1], "Error") {
		return true
	}
	return false
}

// logLevel captures the level of an xray log line ("[Info]", "[Error]", …).
var logLevel = regexp.MustCompile(`^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)\[([A-Za-z]+)\]`)

// firstNonEmptyLine returns the first line of out that is not blank.
func firstNonEmptyLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(l); s != "" {
			return s
		}
	}
	return ""
}
