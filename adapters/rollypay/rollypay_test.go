package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

const (
	apiKey = "rpk_live_abc123def456"
	signer = "whsec_signing_secret_value"
	token  = "adapter-token-for-tests"
	payID  = "pay_a1b2c3d4-e5f6-7890-abcd-ef1234567890"
)

// fakeRolly answers like RollyPay. One payment per order_id; a second create is a 409.
type fakeRolly struct {
	mu       sync.Mutex
	payments map[string]*payment // by order_id
	status   string
	nonces   map[string]bool
	created  []map[string]any
	testMode []bool
	listWrap bool // the list answer is {"data": [...]}
}

func (f *fakeRolly) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nonce := r.Header.Get("X-Nonce")
	if r.Header.Get("X-API-Key") != apiKey || nonce == "" || f.nonces[nonce] {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid key or nonce already used"}`))
		return
	}
	f.nonces[nonce] = true
	f.testMode = append(f.testMode, r.Header.Get("X-Test-Mode") == "true")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/balance":
		_, _ = w.Write([]byte(`{"available_usdt":"1.00","hold_usdt":"0"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/payments":
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.created = append(f.created, in)
		order := in["order_id"].(string)
		if _, ok := f.payments[order]; ok {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"order_id already exists"}`))
			return
		}
		p := &payment{ID: payID, OrderID: order, Status: "created", PayURL: "https://pay.rollypay.io/pay/tok_1",
			Amount: json.Number(in["amount"].(string)), Currency: in["payment_currency"].(string)}
		f.payments[order] = p
		_ = json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodGet && r.URL.Path == "/payments":
		items := []*payment{}
		if p, ok := f.payments[r.URL.Query().Get("order_id")]; ok {
			items = append(items, p)
		}
		if f.listWrap {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": items, "total": len(items)})
		} else {
			_ = json.NewEncoder(w).Encode(items)
		}
	case r.Method == http.MethodGet && r.URL.Path == "/payments/"+payID:
		for _, p := range f.payments {
			c := *p
			if f.status != "" {
				c.Status = f.status
			}
			_ = json.NewEncoder(w).Encode(c)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}
}

type env struct {
	t    *testing.T
	fake *fakeRolly
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fake: &fakeRolly{payments: map[string]*payment{}, nonces: map[string]bool{}}, logs: &bytes.Buffer{}}
	srv := httptest.NewServer(e.fake)
	t.Cleanup(srv.Close)
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.h, err = adapter.NewHandler(&rollyPay{api: srv.URL, hc: srv.Client(), manifest: m}, token, slog.New(slog.NewTextHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, secret := range []string{apiKey, signer} {
			if strings.Contains(e.logs.String(), secret) {
				t.Errorf("%q is in the log", secret)
			}
		}
	})
	return e
}

func (e *env) call(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		e.t.Fatalf("%s %s: not JSON: %q", method, path, w.Body.String())
	}
	return w.Code, out
}

func settings(kv ...any) map[string]any {
	s := map[string]any{"api_key": apiKey, "signing_secret": signer}
	for i := 0; i+1 < len(kv); i += 2 {
		s[kv[i].(string)] = kv[i+1]
	}
	return s
}

func invoiceBody(s map[string]any) map[string]any {
	return map[string]any{"settings": s, "payment_id": 4217, "idempotency_key": "mikan-4217", "amount": 19900, "currency": "RUB",
		"description": "VPN · Месяц", "return_url": "https://panel.example.com/tg"}
}

func wantError(t *testing.T, code int, out map[string]any, wantCode int, wantErr string) {
	t.Helper()
	if code != wantCode || out["code"] != wantErr {
		t.Fatalf("got %d %v, want %d %s", code, out, wantCode, wantErr)
	}
}

func TestInfo(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodGet, "/v1/info", nil)
	if code != http.StatusOK || out["id"] != "rollypay" || out["protocol"] != 1.0 {
		t.Fatalf("info: %d %v", code, out)
	}
	secrets := map[string]bool{}
	for _, f := range out["settings"].([]any) {
		m := f.(map[string]any)
		secrets[m["key"].(string)] = m["secret"].(bool)
	}
	if !secrets["api_key"] || !secrets["signing_secret"] || secrets["method"] || secrets["test"] {
		t.Fatalf("secret flags: %v", secrets)
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("good key: %d %v", code, out)
	}
	code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings("api_key", "rpk_live_wrong")})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadCredentials)
	if strings.Contains(out["message"].(string), "nonce") {
		t.Fatalf("the provider's text leaked: %v", out)
	}
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings("method", "bitcoin")})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
}

func TestCreateInvoice(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	if code != http.StatusOK || out["external_id"] != payID || out["pay_url"] != "https://pay.rollypay.io/pay/tok_1" {
		t.Fatalf("invoice: %d %v", code, out)
	}
	in := e.fake.created[0]
	if in["amount"] != "199.00" || in["payment_currency"] != "RUB" || in["order_id"] != "mikan-4217" ||
		in["success_redirect_url"] != "https://panel.example.com/tg" || in["fail_redirect_url"] != "https://panel.example.com/tg" {
		t.Fatalf("request: %v", in)
	}
	if _, ok := in["payment_method"]; ok {
		t.Fatal("a method was sent although none is set")
	}
	if _, ok := in["test"]; ok || e.fake.testMode[0] {
		t.Fatal("sandbox without the setting")
	}

	// The same key again: the first payment comes back, no second one is made.
	for _, wrap := range []bool{false, true} {
		e.fake.listWrap = wrap
		code, out = e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
		if code != http.StatusOK || out["external_id"] != payID {
			t.Fatalf("retry (wrapped list %v): %d %v", wrap, code, out)
		}
	}
	if len(e.fake.payments) != 1 {
		t.Fatalf("%d payments for one key", len(e.fake.payments))
	}

	// A closed payment under the key is not handed out again.
	e.fake.payments["mikan-4217"].Status = "expired"
	code, out = e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	wantError(t, code, out, http.StatusUnprocessableEntity, "rollypay_order_exists")
}

func TestCreateInvoiceMethodAndSandbox(t *testing.T) {
	e := newEnv(t)
	b := invoiceBody(settings("method", "sbp", "test", true))
	b["idempotency_key"] = "mikan-4218"
	if code, out := e.call(http.MethodPost, "/v1/invoices", b); code != http.StatusOK {
		t.Fatalf("invoice: %d %v", code, out)
	}
	in := e.fake.created[0]
	if in["payment_method"] != "sbp" || in["test"] != true || !e.fake.testMode[0] {
		t.Fatalf("request: %v, test header %v", in, e.fake.testMode)
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	for status, want := range map[string]string{"created": "pending", "processing": "pending", "paid": "paid",
		"expired": "canceled", "canceled": "canceled", "chargeback": "canceled", "refunded": "canceled", "new-thing": "pending"} {
		e.fake.status = status
		code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": payID})
		if code != http.StatusOK || out["status"] != want || out["amount"] != 19900.0 || out["currency"] != "RUB" {
			t.Fatalf("%s: %d %v", status, code, out)
		}
	}
	code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "pay_other"})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "../balance"})
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func sign(secret, ts, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "." + body))
	return hex.EncodeToString(m.Sum(nil))
}

func (e *env) webhook(headers map[string][]string, body string) (int, map[string]any) {
	return e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "remote_ip": "203.0.113.5",
		"headers": headers, "body": base64.StdEncoding.EncodeToString([]byte(body))})
}

func TestWebhook(t *testing.T) {
	e := newEnv(t)
	const ts = "1767225600"
	paid := `{"event_type":"payment.paid","payment_id":"` + payID + `","order_id":"mikan-4217","status":"paid","amount":"199.00","currency":"RUB"}`
	signed := func(secret, ts, body string) map[string][]string {
		return map[string][]string{"X-Timestamp": {ts}, "X-Signature": {sign(secret, ts, body)}}
	}

	code, out := e.webhook(signed(signer, ts, paid), paid)
	if code != http.StatusOK || out["external_id"] != payID {
		t.Fatalf("paid: %d %v", code, out)
	}
	// Other events are not ours to act on.
	expired := strings.Replace(paid, "payment.paid", "payment.expired", 1)
	code, out = e.webhook(signed(signer, ts, expired), expired)
	if code != http.StatusOK || len(out) != 0 {
		t.Fatalf("expired: %d %v", code, out)
	}
	// Forged: wrong secret, changed body, changed timestamp, missing or malformed headers.
	for name, h := range map[string]map[string][]string{
		"wrong secret":   signed("guess", ts, paid),
		"other body":     signed(signer, ts, expired),
		"other time":     {"X-Timestamp": {"1767225601"}, "X-Signature": {sign(signer, ts, paid)}},
		"no signature":   {"X-Timestamp": {ts}},
		"no timestamp":   {"X-Signature": {sign(signer, ts, paid)}},
		"not hex":        {"X-Timestamp": {ts}, "X-Signature": {"zz"}},
		"no headers":     {},
		"api key as sig": {"X-Timestamp": {ts}, "X-Signature": {apiKey}},
	} {
		code, out = e.webhook(h, paid)
		if code != http.StatusBadRequest || out["code"] != adapter.CodeBadRequest {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// Right signature, nonsense body.
	for _, body := range []string{`not json`, `{"event_type":"payment.paid","payment_id":"../x"}`} {
		code, out = e.webhook(signed(signer, ts, body), body)
		wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	}
}
