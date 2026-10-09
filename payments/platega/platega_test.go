package main

import (
	"bytes"
	"encoding/base64"
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
	merchant = "1a021d91-9b26-4762-b303-5d4aac74e921"
	secret   = "platega-secret-value"
	token    = "adapter-token-for-tests"
	txID     = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
)

// fakePlatega answers like Platega for one transaction the test sets up.
type fakePlatega struct {
	mu       sync.Mutex
	status   string
	amount   json.Number
	currency string
	paths    []string
	created  []map[string]any
}

func (f *fakePlatega) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-MerchantId") != merchant || r.Header.Get("X-Secret") != secret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodPost && (r.URL.Path == "/v2/transaction/process" || r.URL.Path == "/transaction/process"):
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.created = append(f.created, in)
		_ = json.NewEncoder(w).Encode(map[string]any{"transactionId": txID, "status": "PENDING", "url": "https://pay.platega.io/?id=" + txID})
	case r.Method == http.MethodGet && r.URL.Path == "/transaction/"+txID:
		_ = json.NewEncoder(w).Encode(map[string]any{"id": txID, "status": f.status,
			"paymentDetails": map[string]any{"amount": f.amount, "currency": f.currency}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type env struct {
	t    *testing.T
	fake *fakePlatega
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fake: &fakePlatega{status: "PENDING", amount: "199", currency: "RUB"}, logs: &bytes.Buffer{}}
	srv := httptest.NewServer(e.fake)
	t.Cleanup(srv.Close)
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.h, err = adapter.NewHandler(&platega{api: srv.URL, hc: srv.Client(), manifest: m}, token, slog.New(slog.NewTextHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if strings.Contains(e.logs.String(), secret) {
			t.Error("the secret key is in the log")
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

func settings(extra ...string) map[string]any {
	s := map[string]any{"merchant_id": merchant, "secret": secret}
	if len(extra) == 2 {
		s[extra[0]] = extra[1]
	}
	return s
}

func wantError(t *testing.T, code int, out map[string]any, wantCode int, wantErr string) {
	t.Helper()
	if code != wantCode || out["code"] != wantErr {
		t.Fatalf("got %d %v, want %d %s", code, out, wantCode, wantErr)
	}
}

func invoiceBody(s map[string]any) map[string]any {
	return map[string]any{"settings": s, "payment_id": 4217, "idempotency_key": "mikan-4217", "amount": 19900, "currency": "RUB",
		"description": "VPN · Месяц", "return_url": "https://panel.example.com/tg"}
}

func TestInfo(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodGet, "/v1/info", nil)
	if code != http.StatusOK || out["id"] != "platega" || out["protocol"] != 1.0 {
		t.Fatalf("info: %d %v", code, out)
	}
	if got, _ := json.Marshal(out["capabilities"]); string(got) != `["webhook"]` {
		t.Fatalf("capabilities: %s", got)
	}
	secrets := map[string]bool{}
	for _, f := range out["settings"].([]any) {
		m := f.(map[string]any)
		secrets[m["key"].(string)] = m["secret"].(bool)
	}
	if !secrets["secret"] || secrets["merchant_id"] || secrets["method"] {
		t.Fatalf("secret flags: %v", secrets)
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("good credentials: %d %v", code, out)
	}
	bad := settings()
	bad["secret"] = "wrong"
	code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": bad})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadCredentials)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings("method", "5")})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"merchant_id": "not-a-uuid", "secret": secret}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
}

func TestCreateInvoice(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	if code != http.StatusOK || out["external_id"] != txID || !strings.HasPrefix(out["pay_url"].(string), "https://pay.platega.io/") {
		t.Fatalf("invoice: %d %v", code, out)
	}
	in := e.fake.created[0]
	pd := in["paymentDetails"].(map[string]any)
	if e.fake.paths[0] != "POST /v2/transaction/process" || pd["amount"] != 199.0 || pd["currency"] != "RUB" ||
		in["return"] != "https://panel.example.com/tg" || in["failedUrl"] != "https://panel.example.com/tg" ||
		in["orderId"] != "mikan-4217" || in["description"] != "VPN · Месяц" {
		t.Fatalf("request: %v %v", e.fake.paths, in)
	}
	if _, ok := in["paymentMethod"]; ok {
		t.Fatal("a method was sent although none is set")
	}

	// A chosen method goes to the endpoint that takes it.
	code, out = e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings("method", "14")))
	if code != http.StatusOK {
		t.Fatalf("with method: %d %v", code, out)
	}
	in = e.fake.created[1]
	if e.fake.paths[1] != "POST /transaction/process" || in["paymentMethod"] != 14.0 {
		t.Fatalf("method request: %v %v", e.fake.paths, in)
	}

	// Platega needs a return URL.
	b := invoiceBody(settings())
	b["return_url"] = ""
	code, out = e.call(http.MethodPost, "/v1/invoices", b)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)

	// Only RUB.
	b = invoiceBody(settings())
	b["currency"] = "USD"
	code, out = e.call(http.MethodPost, "/v1/invoices", b)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	for status, want := range map[string]string{"PENDING": "pending", "CONFIRMED": "paid", "CANCELED": "canceled", "CHARGEBACKED": "canceled", "NEW": "pending"} {
		e.fake.status = status
		code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": txID})
		if code != http.StatusOK || out["status"] != want || out["amount"] != 19900.0 || out["currency"] != "RUB" {
			t.Fatalf("%s: %d %v", status, code, out)
		}
	}
	e.fake.amount = "199.5"
	_, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": txID})
	if out["amount"] != 19950.0 {
		t.Fatalf("fractional amount: %v", out)
	}
	// What Platega really sends: sixteen decimals, the buyer's fee included.
	e.fake.amount = "177.4500000000000000"
	_, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": txID})
	if out["amount"] != 17745.0 {
		t.Fatalf("amount with trailing zeros: %v", out)
	}
	// Past the cents only zeros may follow.
	e.fake.amount = "177.4510000000000000"
	code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": txID})
	wantError(t, code, out, http.StatusBadGateway, adapter.CodeProviderUnavailable)
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "00000000-0000-0000-0000-000000000001"})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "../etc"})
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func (e *env) webhook(headers map[string][]string, body string) (int, map[string]any) {
	return e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "remote_ip": "203.0.113.5",
		"headers": headers, "body": base64.StdEncoding.EncodeToString([]byte(body))})
}

func TestWebhook(t *testing.T) {
	e := newEnv(t)
	good := map[string][]string{"X-Merchantid": {merchant}, "X-Secret": {secret}}
	confirmed := `{"id":"` + txID + `","amount":199,"currency":"RUB","status":"CONFIRMED","paymentMethod":2}`

	code, out := e.webhook(good, confirmed)
	if code != http.StatusOK || out["external_id"] != txID {
		t.Fatalf("confirmed: %d %v", code, out)
	}
	// Other statuses are not ours to act on.
	code, out = e.webhook(good, strings.Replace(confirmed, "CONFIRMED", "CANCELED", 1))
	if code != http.StatusOK || len(out) != 0 {
		t.Fatalf("canceled: %d %v", code, out)
	}
	// Forged: wrong or missing credentials.
	code, out = e.webhook(map[string][]string{"X-Merchantid": {merchant}, "X-Secret": {"guess"}}, confirmed)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	code, out = e.webhook(map[string][]string{}, confirmed)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	code, out = e.webhook(map[string][]string{"X-Merchantid": {"other"}, "X-Secret": {secret}}, confirmed)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	// Right credentials, nonsense body.
	code, out = e.webhook(good, `not json`)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	code, out = e.webhook(good, `{"id":"x","status":"CONFIRMED"}`)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func TestAuthRequired(t *testing.T) {
	e := newEnv(t)
	r := httptest.NewRequest(http.MethodGet, "/v1/info", nil)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
}
