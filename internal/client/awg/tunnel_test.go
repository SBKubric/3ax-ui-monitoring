package awg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
)

// serverPort is the port the in-tunnel stub of mon-server listens on. Any
// port does; 8443 only reads like the real thing.
const serverPort = 8443

// TestProbeThroughTunnel is the success path of spec §5 without a single
// packet leaving this process: two netstack devices — the mon-client under
// test and a stand-in for the AWG server — hold a real AmneziaWG tunnel over
// loopback UDP, and mon-server's tunnel probe is answered from inside it.
//
// It pins what a good AWG probe looks like on the wire: ok, an egressIp
// that is the tunnel address the packets really came from, and all four
// timings measured (spec §5, protocol §5.3).
func TestProbeThroughTunnel(t *testing.T) {
	t.Parallel()

	serverPrivB64, serverPubB64, _ := keypair(t)
	clientPrivB64, clientPubB64, _ := keypair(t)
	port := freeUDPPort(t)

	// The far end: a device listening on loopback UDP that knows our
	// public key, with an HTTPS echo of GET /v1/probe behind it.
	serverCfg := parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
ListenPort = %d
%s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, serverTunnelIP, serverPrivB64, port, awgObfuscation, clientPubB64, clientTunnelIP))
	server, err := Open(serverCfg)
	if err != nil {
		t.Fatalf("open server device: %v", err)
	}
	defer server.Close()

	cert, pool := selfSigned(t, serverTunnelIP)
	ln, err := server.tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverTunnelIP), Port: serverPort})
	if err != nil {
		t.Fatalf("listen inside the tunnel: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(probeEcho)}
	go httpSrv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}))
	t.Cleanup(func() { _ = httpSrv.Close() })

	// The near end: exactly the config mon-client would get from
	// mon-server, pointing at the far end's loopback endpoint.
	clientCfg := parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
MTU = 1420
%s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%d
`, clientTunnelIP, clientPrivB64, awgObfuscation, serverPubB64, port))

	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: pool}}
	key := proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "direct"}
	b := probe.Budgets{Budget: 20 * time.Second, Connect: 5 * time.Second, TLS: 5 * time.Second, Headers: 5 * time.Second}

	res := p.Probe(context.Background(), fmt.Sprintf("https://%s:%d/v1/probe", serverTunnelIP, serverPort), "tok", key, clientCfg, b)
	if !res.Ok {
		t.Fatalf("probe failed: reason=%q detail=%q", deref(res.Reason), deref(res.Detail))
	}
	for name, v := range map[string]*int64{
		"handshakeMs": res.HandshakeMs,
		"connectMs":   res.ConnectMs,
		"tlsMs":       res.TlsMs,
		"ttfbMs":      res.TtfbMs,
	} {
		if v == nil {
			t.Errorf("%s is null, want a measurement", name)
			continue
		}
		if *v < 0 || *v > b.Budget.Milliseconds() {
			t.Errorf("%s = %d, out of range", name, *v)
		}
	}
	if res.EgressIp == nil || *res.EgressIp != clientTunnelIP {
		t.Errorf("egressIp = %v, want %q", res.EgressIp, clientTunnelIP)
	}
	if res.Reason != nil || res.Detail != nil {
		t.Errorf("a successful probe carries reason=%v detail=%v", res.Reason, res.Detail)
	}
	if res.TargetKey != key {
		t.Errorf("target key = %v, want %v", res.TargetKey, key)
	}
}

// TestProbeThroughTunnelWrongNonce is spec §5's http_error: mon-server
// answered, but with someone else's nonce, so the response cannot be
// attributed to this probe.
func TestProbeThroughTunnelWrongNonce(t *testing.T) {
	t.Parallel()

	serverPrivB64, serverPubB64, _ := keypair(t)
	clientPrivB64, clientPubB64, _ := keypair(t)
	port := freeUDPPort(t)

	serverCfg := parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
ListenPort = %d
%s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, serverTunnelIP, serverPrivB64, port, awgObfuscation, clientPubB64, clientTunnelIP))
	server, err := Open(serverCfg)
	if err != nil {
		t.Fatalf("open server device: %v", err)
	}
	defer server.Close()

	cert, pool := selfSigned(t, serverTunnelIP)
	ln, err := server.tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverTunnelIP), Port: serverPort})
	if err != nil {
		t.Fatalf("listen inside the tunnel: %v", err)
	}
	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEcho(w, r, "someone-elses-nonce")
	})}
	go httpSrv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}))
	t.Cleanup(func() { _ = httpSrv.Close() })

	clientCfg := parseConf(t, fmt.Sprintf(`[Interface]
Address = %s/32
PrivateKey = %s
%s

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%d
`, clientTunnelIP, clientPrivB64, awgObfuscation, serverPubB64, port))

	p := Prober{Log: silent(), tlsConfig: &tls.Config{RootCAs: pool}}
	res := p.Probe(context.Background(), fmt.Sprintf("https://%s:%d/v1/probe", serverTunnelIP, serverPort), "tok",
		proto.TargetKey{InboundKind: "awg", InboundID: 7, Path: "direct"}, clientCfg,
		probe.Budgets{Budget: 20 * time.Second, Connect: 5 * time.Second, TLS: 5 * time.Second, Headers: 5 * time.Second})

	if res.Ok {
		t.Fatal("a probe whose nonce was not echoed back counted as a success")
	}
	if got := deref(res.Reason); got != proto.ReasonHTTPError {
		t.Errorf("reason = %q, want %q", got, proto.ReasonHTTPError)
	}
	if res.HandshakeMs == nil || res.TlsMs == nil {
		t.Error("a failure after TLS must still carry the phases it did measure")
	}
}

// probeEcho is GET /v1/probe as mon-server implements it (protocol §5.2).
func probeEcho(w http.ResponseWriter, r *http.Request) { writeEcho(w, r, r.URL.Query().Get("n")) }

func writeEcho(w http.ResponseWriter, r *http.Request, nonce string) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.ProbeEcho{
		Nonce:    nonce,
		EgressIp: host,
		ServerTs: time.Now().UnixMilli(),
	})
}

// parseConf is the tests' shorthand for a `.conf` that must be valid.
func parseConf(t *testing.T, conf string) *config.AWGConfig {
	t.Helper()
	cfg, err := config.ParseAWGConf(conf)
	if err != nil {
		t.Fatalf("ParseAWGConf: %v\n%s", err, conf)
	}
	return cfg
}

// freeUDPPort picks a loopback UDP port the far-end device can listen on.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// selfSigned mints a throwaway certificate for an IP, plus the pool that
// trusts it. The real mon-server has a publicly trusted certificate; these
// tests only need the probe's TLS handshake to be a real one.
func selfSigned(t *testing.T, ip string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: ip},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool.AddCert(parsed)
	return cert, pool
}
