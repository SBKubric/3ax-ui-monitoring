package tg

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTP_SendTo_Success checks the happy path: the request goes to
// POST <apiBase>/bot<token>/sendMessage with a JSON {chat_id, text} body,
// and a 200 {"ok":true} response is not an error.
func TestHTTP_SendTo_Success(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody sendMessageRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
	}))
	defer srv.Close()

	h := NewHTTP(nil, srv.URL)
	if err := h.SendTo(context.Background(), "123:ABC", "42", "hello"); err != nil {
		t.Fatalf("SendTo: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/bot123:ABC/sendMessage" {
		t.Errorf("path = %q, want /bot123:ABC/sendMessage", gotPath)
	}
	if gotBody.ChatID != "42" || gotBody.Text != "hello" {
		t.Errorf("body = %+v, want {ChatID:42 Text:hello}", gotBody)
	}
}

// TestHTTP_SendTo_BadRequestCarriesDescription checks that a documented
// Telegram rejection (400, ok:false) surfaces Telegram's own description in
// the returned error, so a caller's log line explains *why* delivery
// failed instead of just "non-200".
func TestHTTP_SendTo_BadRequestCarriesDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`))
	}))
	defer srv.Close()

	h := NewHTTP(nil, srv.URL)
	err := h.SendTo(context.Background(), "123:ABC", "bogus", "hello")
	if err == nil {
		t.Fatal("SendTo returned no error for a 400 response")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("error = %q, want it to contain Telegram's description", err)
	}
	if strings.Contains(err.Error(), "123:ABC") {
		t.Fatalf("error = %q, must never contain the bot token", err)
	}
}

// TestHTTP_SendTo_ServerErrorIsAnError checks that a 5xx (Telegram itself
// down, or a proxy in front of it) is reported as an error even with no
// parseable body, so a caller cannot mistake it for success.
func TestHTTP_SendTo_ServerErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	h := NewHTTP(nil, srv.URL)
	err := h.SendTo(context.Background(), "123:ABC", "42", "hello")
	if err == nil {
		t.Fatal("SendTo returned no error for a 502 response")
	}
	if strings.Contains(err.Error(), "123:ABC") {
		t.Fatalf("error = %q, must never contain the bot token", err)
	}
}

// TestHTTP_SendTo_TransportErrorNeverLeaksToken checks that even a
// connection-level failure (no server listening) — whose default net/url
// error text embeds the full request URL, token included — comes back with
// the token scrubbed out.
func TestHTTP_SendTo_TransportErrorNeverLeaksToken(t *testing.T) {
	h := NewHTTP(nil, "http://127.0.0.1:1") // nothing listens here
	err := h.SendTo(context.Background(), "secret-token", "42", "hello")
	if err == nil {
		t.Fatal("SendTo returned no error against an unreachable server")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error = %q, must never contain the bot token", err)
	}
}
