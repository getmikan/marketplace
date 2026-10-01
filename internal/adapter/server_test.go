package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const token = "s3cret-adapter-token"

// stub is a provider that records what reached it.
type stub struct {
	calls   int
	err     error
	refunds bool
	webhook WebhookRequest
}

func (s *stub) Info() Info {
	caps := []string{CapWebhook}
	if s.refunds {
		caps = append(caps, CapRefund)
	}
	return Info{ID: "stub", Protocol: Protocol, Version: "1.0.0", Name: Text{"en": "Stub"}, Currencies: []string{"RUB"}, Capabilities: caps,
		Settings: []Setting{
			{Key: "key", Type: "string", Secret: true, Required: true, Pattern: `^[a-z]+$`},
			{Key: "test", Type: "bool"},
		}}
}

func (s *stub) Check(context.Context, Settings) error { s.calls++; return s.err }

func (s *stub) CreateInvoice(_ context.Context, r InvoiceRequest) (Invoice, error) {
	s.calls++
	return Invoice{ExternalID: "ext-" + r.IdempotencyKey, PayURL: "https://pay.example/" + r.IdempotencyKey}, s.err
}

func (s *stub) Status(context.Context, Settings, string) (Status, error) {
	s.calls++
	return Status{Status: StatusPaid, Amount: 100, Currency: "RUB"}, s.err
}

func (s *stub) Webhook(_ context.Context, r WebhookRequest) (string, error) {
	s.calls++
	s.webhook = r
	return "ext-1", s.err
}

type refundingStub struct{ stub }

func (s *refundingStub) Refund(context.Context, Settings, string, int64) error {
	s.calls++
	return s.err
}

func handler(t *testing.T, p Provider) (http.Handler, *bytes.Buffer) {
	t.Helper()
	logs := &bytes.Buffer{}
	h, err := NewHandler(p, token, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h, logs
}

func do(h http.Handler, method, path, auth string, body io.Reader) (int, map[string]any, http.Header) {
	r := httptest.NewRequest(method, path, body)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func post(h http.Handler, path string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	code, out, _ := do(h, http.MethodPost, path, "Bearer "+token, bytes.NewReader(raw))
	return code, out
}

var good = map[string]any{"key": "abc"}

func TestAuth(t *testing.T) {
	p := &stub{}
	h, _ := handler(t, p)
	for name, auth := range map[string]string{
		"missing":      "",
		"wrong":        "Bearer not-the-token",
		"prefix":       "Bearer " + token[:5],
		"longer":       "Bearer " + token + "x",
		"basic":        "Basic " + token,
		"bare token":   token,
		"empty bearer": "Bearer ",
	} {
		for _, path := range []string{"/v1/info", "/v1/check", "/nope"} {
			code, out, hdr := do(h, http.MethodGet, path, auth, nil)
			if code != http.StatusUnauthorized || out["code"] != CodeUnauthorized || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("%s %s: %d %v", name, path, code, out)
			}
		}
	}
	if p.calls != 0 {
		t.Fatal("an unauthorized request reached the provider")
	}
	for _, auth := range []string{"Bearer " + token, "bearer " + token} {
		if code, out, _ := do(h, http.MethodGet, "/v1/info", auth, nil); code != http.StatusOK || out["id"] != "stub" {
			t.Fatalf("%q: %d %v", auth, code, out)
		}
	}
}

func TestRouting(t *testing.T) {
	h, _ := handler(t, &stub{})
	if code, out, _ := do(h, http.MethodGet, "/v1/nope", "Bearer "+token, nil); code != http.StatusNotFound || out["code"] != CodeNotFound {
		t.Fatalf("unknown path: %d %v", code, out)
	}
	if code, out, _ := do(h, http.MethodGet, "/v1/check", "Bearer "+token, nil); code != http.StatusMethodNotAllowed || out["code"] != "method_not_allowed" {
		t.Fatalf("GET check: %d %v", code, out)
	}
	if code, out, _ := do(h, http.MethodPost, "/v1/info", "Bearer "+token, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST info: %d %v", code, out)
	}
	// Without the refund capability there is no refund endpoint.
	if code, out := post(h, "/v1/refund", map[string]any{"settings": good, "external_id": "x", "amount": 1}); code != http.StatusNotFound || out["code"] != CodeNotFound {
		t.Fatalf("refund: %d %v", code, out)
	}
	r := &refundingStub{stub{refunds: true}}
	h, _ = handler(t, r)
	if code, out := post(h, "/v1/refund", map[string]any{"settings": good, "external_id": "x", "amount": 1}); code != http.StatusOK || r.calls != 1 {
		t.Fatalf("refund: %d %v", code, out)
	}
	if code, out := post(h, "/v1/refund", map[string]any{"settings": good, "external_id": "x", "amount": 0}); code != http.StatusBadRequest {
		t.Fatalf("refund of 0: %d %v", code, out)
	}
}

func TestInfoMustBeCoherent(t *testing.T) {
	if _, err := NewHandler(&stub{refunds: true}, token, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("the refund capability without Refund was accepted")
	}
	if _, err := NewHandler(&refundingStub{stub{refunds: true}}, token, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsChecked(t *testing.T) {
	p := &stub{}
	h, _ := handler(t, p)
	for name, s := range map[string]any{
		"missing":       map[string]any{},
		"empty":         map[string]any{"key": ""},
		"pattern":       map[string]any{"key": "ABC"},
		"not a string":  map[string]any{"key": 5},
		"bool mistyped": map[string]any{"key": "abc", "test": "true"},
		"no settings":   nil,
	} {
		code, out := post(h, "/v1/check", map[string]any{"settings": s})
		if code != http.StatusUnprocessableEntity || out["code"] != CodeBadSettings {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	if p.calls != 0 {
		t.Fatal("bad settings reached the provider")
	}
	if code, out := post(h, "/v1/check", map[string]any{"settings": map[string]any{"key": "abc", "test": true, "unknown": 1}}); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("good settings: %d %v", code, out)
	}
}

func TestInvoiceChecked(t *testing.T) {
	p := &stub{}
	h, _ := handler(t, p)
	ok := func() map[string]any {
		return map[string]any{"settings": good, "payment_id": 4217, "idempotency_key": "mikan-4217", "amount": 19900, "currency": "RUB",
			"return_url": "https://panel.example/tg", "webhook_url": "https://panel.example/pay/addon/stub/t"}
	}
	if code, out := post(h, "/v1/invoices", ok()); code != http.StatusOK || out["external_id"] != "ext-mikan-4217" {
		t.Fatalf("good invoice: %d %v", code, out)
	}
	for field, v := range map[string]any{
		"payment_id":      0,
		"idempotency_key": strings.Repeat("k", 65),
		"amount":          -1,
		"currency":        "USD",
		"return_url":      "javascript:alert(1)",
		"webhook_url":     "/relative",
	} {
		req := ok()
		req[field] = v
		if code, out := post(h, "/v1/invoices", req); code != http.StatusBadRequest || out["code"] != CodeBadRequest {
			t.Fatalf("%s=%v: %d %v", field, v, code, out)
		}
	}
	req := ok()
	req["idempotency_key"] = "with space"
	if code, _ := post(h, "/v1/invoices", req); code != http.StatusBadRequest {
		t.Fatalf("key with a space: %d", code)
	}
	if p.calls != 1 {
		t.Fatalf("bad invoices reached the provider: %d calls", p.calls)
	}
}

func TestBodies(t *testing.T) {
	h, _ := handler(t, &stub{})
	big := `{"settings":{"key":"abc"},"pad":"` + strings.Repeat("x", MaxBody) + `"}`
	code, out, _ := do(h, http.MethodPost, "/v1/check", "Bearer "+token, strings.NewReader(big))
	if code != http.StatusBadRequest || !strings.Contains(out["message"].(string), "1 MiB") {
		t.Fatalf("big body: %d %v", code, out)
	}
	code, out, _ = do(h, http.MethodPost, "/v1/check", "Bearer "+token, strings.NewReader(`{"settings":`))
	if code != http.StatusBadRequest || out["code"] != CodeBadRequest {
		t.Fatalf("broken JSON: %d %v", code, out)
	}
}

func TestWebhookHeadersCanonical(t *testing.T) {
	p := &stub{}
	h, _ := handler(t, p)
	code, out := post(h, "/v1/webhook", map[string]any{"settings": good, "remote_ip": "203.0.113.7",
		"headers": map[string][]string{"x-signature": {"abc"}}, "body": []byte(`{"a":1}`)})
	if code != http.StatusOK || out["external_id"] != "ext-1" {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if p.webhook.Headers.Get("X-Signature") != "abc" || string(p.webhook.Body) != `{"a":1}` || p.webhook.RemoteIP != "203.0.113.7" {
		t.Fatalf("webhook request: %+v", p.webhook)
	}
}

func TestErrors(t *testing.T) {
	p := &stub{err: BadCredentials("refused")}
	h, logs := handler(t, p)
	if code, out := post(h, "/v1/check", map[string]any{"settings": good}); code != http.StatusUnprocessableEntity || out["code"] != CodeBadCredentials || out["message"] != "refused" {
		t.Fatalf("provider error: %d %v", code, out)
	}
	// A transport error is not shown: it carries URLs and addresses.
	p.err = errors.New(`Post "https://api.example/x?token=abc": dial tcp 10.0.0.1:443: connection refused`)
	code, out := post(h, "/v1/check", map[string]any{"settings": good})
	if code != http.StatusBadGateway || out["code"] != CodeProviderUnavailable || strings.Contains(out["message"].(string), "10.0.0.1") {
		t.Fatalf("transport error: %d %v", code, out)
	}
	p.err = context.DeadlineExceeded
	if _, out := post(h, "/v1/check", map[string]any{"settings": good}); !strings.Contains(out["message"].(string), "in time") {
		t.Fatalf("timeout: %v", out)
	}
	if strings.Contains(logs.String(), "abc") || strings.Contains(logs.String(), token) {
		t.Fatalf("settings or the token in the log: %s", logs)
	}
}

func TestCheckListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:41873", "[::1]:41873", "127.0.0.2:1", "127.0.0.1:65535"} {
		if err := CheckListen(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"", "0.0.0.0:41873", "[::]:41873", ":41873", "192.168.1.5:41873", "8.8.8.8:80",
		"127.0.0.1:0", "127.0.0.1", "localhost:41873", "127.0.0.1:65536", "127.0.0.1:-1", "127.0.0.1:http", "[fe80::1%eth0]:41873"} {
		if err := CheckListen(addr); err == nil {
			t.Errorf("%q was accepted", addr)
		}
	}
}

func TestRunRefuses(t *testing.T) {
	for _, c := range []struct{ listen, token string }{
		{"0.0.0.0:41873", token},
		{"127.0.0.1:0", token},
		{"127.0.0.1:41873", ""},
	} {
		t.Setenv("MIKAN_ADAPTER_LISTEN", c.listen)
		t.Setenv("MIKAN_ADAPTER_TOKEN", c.token)
		if err := Run(&stub{}); err == nil {
			t.Fatalf("Run started with %+v", c)
		}
	}
}
