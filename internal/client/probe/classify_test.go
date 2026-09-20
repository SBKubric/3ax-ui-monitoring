package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

func ms(v int64) *int64 { return &v }

func TestClassify(t *testing.T) {
	b := Budgets{Budget: 20 * time.Second, Connect: time.Second, TLS: 2 * time.Second, Headers: 2 * time.Second}

	cases := []struct {
		name   string
		err    error
		ph     Phases
		want   string
		detail string // substring the detail must carry
	}{
		{name: "success", err: nil, want: ""},
		{
			name: "nonce mismatch",
			err:  &url.Error{Op: "Get", URL: "u", Err: &NonceMismatchError{Want: "a", Got: "b"}},
			ph:   Phases{ConnectMs: ms(1), TlsMs: ms(30), TtfbMs: ms(20)},
			want: proto.ReasonHTTPError, detail: "nonce mismatch",
		},
		{
			name: "non-200",
			err:  &HTTPStatusError{Status: 401, Body: `{"error":"token_revoked"}`},
			ph:   Phases{ConnectMs: ms(1), TlsMs: ms(30)},
			want: proto.ReasonHTTPError, detail: "token_revoked",
		},
		{
			name: "dial refused",
			err:  &url.Error{Op: "Get", URL: "u", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}},
			want: proto.ReasonTCPRefused,
		},
		{
			name: "dial timed out",
			err:  &url.Error{Op: "Get", URL: "u", Err: &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}},
			want: proto.ReasonTCPTimeout,
		},
		{
			name: "connect slower than the budget",
			err:  errors.New("something after a very slow dial"),
			ph:   Phases{ConnectMs: ms(1500)},
			want: proto.ReasonTCPTimeout,
		},
		{
			name: "tls handshake timeout",
			err:  &url.Error{Op: "Get", URL: "u", Err: errors.New("net/http: TLS handshake timeout")},
			ph:   Phases{ConnectMs: ms(1)},
			want: proto.ReasonTLSTimeout,
		},
		{
			name: "overall budget",
			err:  &url.Error{Op: "Get", URL: "u", Err: context.DeadlineExceeded},
			ph:   Phases{ConnectMs: ms(1), TlsMs: ms(40)},
			want: proto.ReasonProbeTimeout,
		},
		{
			name: "socks failure before tls",
			err:  errors.New("socks connect tcp 127.0.0.1:10801->mon:443: unknown error general SOCKS server failure"),
			ph:   Phases{ConnectMs: ms(1)},
			want: proto.ReasonTCPRefused,
		},
		{
			// gVisor's netstack (internal/client/awg's dialer) words a
			// refused dial differently from the kernel; both must classify
			// the same way so the AWG probe benefits from this table too.
			name: "gvisor dial refused",
			err:  errors.New("dial tcp 10.66.66.1:8443: connection was refused"),
			want: proto.ReasonTCPRefused,
		},
		{
			name: "broken exchange after tls",
			err:  errors.New("unexpected EOF"),
			ph:   Phases{ConnectMs: ms(1), TlsMs: ms(40)},
			want: proto.ReasonHTTPError,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reason, detail := Classify(c.err, c.ph, b)
			if reason != c.want {
				t.Fatalf("reason = %q, want %q (detail %q)", reason, c.want, detail)
			}
			if c.detail != "" && !strings.Contains(detail, c.detail) {
				t.Errorf("detail = %q, want it to carry %q", detail, c.detail)
			}
			if c.err == nil && detail != "" {
				t.Errorf("detail = %q for a successful probe", detail)
			}
		})
	}
}

func TestClassify_DetailTrimmedToMaxRunes(t *testing.T) {
	err := fmt.Errorf("проба: %s", strings.Repeat("ошибка ", 200))

	_, detail := Classify(err, Phases{ConnectMs: ms(1), TlsMs: ms(2)}, fastBudgets())

	if n := len([]rune(detail)); n != MaxDetail {
		t.Fatalf("detail is %d runes, want %d (protocol §5.3)", n, MaxDetail)
	}
	if !strings.HasPrefix(detail, "проба: ") {
		t.Errorf("detail = %q, want the head of the error text", detail[:20])
	}
}
