package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

const (
	shopID   = "123456"
	ykSecret = "live_ykSECRETvalue000"
	token    = "adapter-token-for-tests"
)

// fakeYooKassa answers like the API with whatever the test put in payments.
type fakeYooKassa struct {
	mu       sync.Mutex
	payments map[string]*ykPayment
	idem     map[string]string // Idempotence-Key → payment id
	created  []map[string]any  // bodies of POST /payments
	refunds  map[string]map[string]any
	refundSt string // status of new refunds
	fail     int    // answer every request with this HTTP status
	failBody string
	n        int
}

func (f *fakeYooKassa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != 0 {
		w.WriteHeader(f.fail)
		_, _ = w.Write([]byte(f.failBody))
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != shopID || pass != ykSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","code":"invalid_credentials"}`))
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	key := r.Header.Get("Idempotence-Key")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/me":
		_ = json.NewEncoder(w).Encode(map[string]string{"account_id": shopID})
	case r.Method == http.MethodPost && r.URL.Path == "/payments":
		if id, ok := f.idem[key]; ok {
			_ = json.NewEncoder(w).Encode(f.payments[id])
			return
		}
		f.created = append(f.created, body)
		amount := body["amount"].(map[string]any)
		f.n++
		p := &ykPayment{ID: "2f1c0000-000f-5000-8000-00000000000" + strconv.Itoa(f.n), Status: "pending",
			Amount: ykAmount{Value: amount["value"].(string), Currency: amount["currency"].(string)}}
		p.Confirmation.URL = "https://yoomoney.ru/checkout/payments/v2/contract?orderId=" + p.ID
		f.payments[p.ID], f.idem[key] = p, p.ID
		_ = json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/payments/"):
		p, ok := f.payments[strings.TrimPrefix(r.URL.Path, "/payments/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"type":"error","code":"not_found"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodPost && r.URL.Path == "/refunds":
		if key == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.refunds[key] = body
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "rf-" + key[:8], "status": f.refundSt})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type env struct {
	t    *testing.T
	yk   *fakeYooKassa
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, logs: &bytes.Buffer{},
		yk: &fakeYooKassa{payments: map[string]*ykPayment{}, idem: map[string]string{}, refunds: map[string]map[string]any{}, refundSt: "succeeded"}}
	srv := httptest.NewServer(e.yk)
	t.Cleanup(srv.Close)
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.h, err = adapter.NewHandler(&yooKassa{api: srv.URL, hc: srv.Client(), manifest: m}, token, slog.New(slog.NewTextHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Whatever a test does, the secret never reaches the log.
	t.Cleanup(func() {
		if strings.Contains(e.logs.String(), ykSecret) {
			t.Error("the secret key is in the log")
		}
	})
	return e
}

// call sends a protocol request; the answer is decoded into a map.
func (e *env) call(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		e.t.Fatalf("%s %s: not JSON: %q", method, path, w.Body.String())
	}
	return w.Code, out
}

func settings() map[string]any { return map[string]any{"shop_id": shopID, "secret_key": ykSecret} }

func (e *env) invoice(key string, amount int64) string {
	e.t.Helper()
	code, out := e.call(http.MethodPost, "/v1/invoices", map[string]any{"settings": settings(), "payment_id": 4217, "idempotency_key": key,
		"amount": amount, "currency": "RUB", "description": "VPN · Месяц", "return_url": "https://panel.example.com/tg"})
	if code != http.StatusOK {
		e.t.Fatalf("invoice: %d %v", code, out)
	}
	return out["external_id"].(string)
}

func manifestVersion(t *testing.T) string {
	t.Helper()
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	return m.Version
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
	if code != http.StatusOK || out["id"] != "yookassa" || out["protocol"] != 1.0 || out["version"] != manifestVersion(t) {
		t.Fatalf("info: %d %v", code, out)
	}
	if got, _ := json.Marshal(out["capabilities"]); string(got) != `["webhook","refund"]` {
		t.Fatalf("capabilities: %s", got)
	}
	if got, _ := json.Marshal(out["currencies"]); string(got) != `["RUB"]` {
		t.Fatalf("currencies: %s", got)
	}
	secret := map[string]bool{}
	for _, s := range out["settings"].([]any) {
		f := s.(map[string]any)
		secret[f["key"].(string)] = f["secret"].(bool)
	}
	if len(secret) != 2 || secret["shop_id"] || !secret["secret_key"] {
		t.Fatalf("settings: %v", out["settings"])
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("good keys: %d %v", code, out)
	}
	code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"shop_id": shopID, "secret_key": "live_wrong"}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadCredentials)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"shop_id": "shop", "secret_key": ykSecret}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"shop_id": shopID}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
}

func TestCreateInvoice(t *testing.T) {
	e := newEnv(t)
	id := e.invoice("mikan-4217", 19900)
	if len(e.yk.created) != 1 {
		t.Fatalf("created %d payments", len(e.yk.created))
	}
	if e.yk.idem["mikan-4217"] != id {
		t.Fatalf("Idempotence-Key: %v", e.yk.idem)
	}
	body, _ := json.Marshal(e.yk.created[0])
	for _, want := range []string{`"amount":{"currency":"RUB","value":"199.00"}`, `"capture":true`,
		`"confirmation":{"return_url":"https://panel.example.com/tg","type":"redirect"}`, `"mikan_payment_id":"4217"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("payment body %s: no %s", body, want)
		}
	}
	// A retry with the same key gets the same payment, not a second one.
	if again := e.invoice("mikan-4217", 19900); again != id || len(e.yk.created) != 1 {
		t.Fatalf("retry: %s, %d payments", again, len(e.yk.created))
	}
	if other := e.invoice("mikan-4218", 50); other == id || e.yk.payments[other].Amount.Value != "0.50" {
		t.Fatalf("second payment: %s %+v", other, e.yk.payments[other])
	}

	req := map[string]any{"settings": settings(), "payment_id": 1, "idempotency_key": "k", "amount": 100, "currency": "USD", "return_url": "https://x.example"}
	code, out := e.call(http.MethodPost, "/v1/invoices", req)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	req["currency"], req["return_url"] = "RUB", ""
	code, out = e.call(http.MethodPost, "/v1/invoices", req)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	id := e.invoice("mikan-1", 19900)
	for ykStatus, want := range map[string]string{"pending": "pending", "waiting_for_capture": "pending", "succeeded": "paid", "canceled": "canceled"} {
		e.yk.payments[id].Status = ykStatus
		code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": id})
		if code != http.StatusOK || out["status"] != want || out["amount"] != 19900.0 || out["currency"] != "RUB" {
			t.Fatalf("%s: %d %v", ykStatus, code, out)
		}
	}
	code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "2f1c0000-dead"})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "../me"})
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	e.yk.payments[id].Amount.Value = "199.999"
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": id})
	wantError(t, code, out, http.StatusBadGateway, adapter.CodeProviderUnavailable)
}

func (e *env) webhook(ip, body string) (int, map[string]any) {
	return e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "remote_ip": ip,
		"headers": map[string][]string{"Content-Type": {"application/json"}}, "body": []byte(body)})
}

func TestWebhook(t *testing.T) {
	e := newEnv(t)
	paid := `{"type":"notification","event":"payment.succeeded","object":{"id":"2f1c-1","status":"succeeded"}}`
	for _, ip := range []string{"185.71.76.10", "77.75.156.11", "::ffff:185.71.77.5", "2a02:5180::1"} {
		if code, out := e.webhook(ip, paid); code != http.StatusOK || out["external_id"] != "2f1c-1" {
			t.Fatalf("from %s: %d %v", ip, code, out)
		}
	}
	for _, ip := range []string{"1.2.3.4", "185.71.76.32", "127.0.0.1", "", "185.71.76.10:443"} {
		code, out := e.webhook(ip, paid)
		wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
	}
	if code, out := e.webhook("185.71.76.10", `{"type":"notification","event":"refund.succeeded","object":{"id":"rf-1","payment_id":"2f1c-1"}}`); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("refund event: %d %v", code, out)
	}
	code, out := e.webhook("185.71.76.10", `not json`)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func TestRefund(t *testing.T) {
	e := newEnv(t)
	id := e.invoice("mikan-1", 19900)
	e.yk.payments[id].Status = "succeeded"
	refund := map[string]any{"settings": settings(), "external_id": id, "amount": 19900}
	for range 2 {
		if code, out := e.call(http.MethodPost, "/v1/refund", refund); code != http.StatusOK || len(out) != 0 {
			t.Fatalf("refund: %d %v", code, out)
		}
	}
	// The retry used the same Idempotence-Key: YooKassa refunds once.
	got, ok := e.yk.refunds[refundKey(id, 19900)]
	if len(e.yk.refunds) != 1 || !ok {
		t.Fatalf("refunds: %v", e.yk.refunds)
	}
	body, _ := json.Marshal(got)
	if want := `{"amount":{"currency":"RUB","value":"199.00"},"payment_id":"` + id + `"}`; string(body) != want {
		t.Fatalf("refund body %s, want %s", body, want)
	}
	if len(refundKey(id, 19900)) > 64 || refundKey(id, 100) == refundKey(id, 19900) {
		t.Fatal("refund keys")
	}

	code, out := e.call(http.MethodPost, "/v1/refund", map[string]any{"settings": settings(), "external_id": "2f1c-none", "amount": 100})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
	e.yk.refundSt = "canceled"
	code, out = e.call(http.MethodPost, "/v1/refund", map[string]any{"settings": settings(), "external_id": id, "amount": 100})
	wantError(t, code, out, http.StatusUnprocessableEntity, "yookassa_refund_canceled")
}

func TestProviderErrors(t *testing.T) {
	e := newEnv(t)
	check := map[string]any{"settings": settings()}

	e.yk.fail, e.yk.failBody = http.StatusBadRequest, `{"type":"error","code":"invalid_request","parameter":"receipt","description":"Receipt is missing"}`
	code, out := e.call(http.MethodPost, "/v1/check", check)
	wantError(t, code, out, http.StatusUnprocessableEntity, "yookassa_invalid_request")
	if msg := out["message"].(string); !strings.Contains(msg, "parameter receipt") {
		t.Fatalf("message: %q", msg)
	}

	e.yk.fail, e.yk.failBody = http.StatusInternalServerError, `oops`
	code, out = e.call(http.MethodPost, "/v1/check", check)
	wantError(t, code, out, http.StatusBadGateway, adapter.CodeProviderUnavailable)

	e.yk.fail, e.yk.failBody = 0, ""
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // nothing listens there now
	m, _ := catalog.ParseManifest(manifestJSON)
	h, _ := adapter.NewHandler(&yooKassa{api: srv.URL, hc: http.DefaultClient, manifest: m}, token, slog.New(slog.NewTextHandler(e.logs, nil)))
	e.h = h
	code, out = e.call(http.MethodPost, "/v1/check", check)
	wantError(t, code, out, http.StatusBadGateway, adapter.CodeProviderUnavailable)
	if strings.Contains(out["message"].(string), "127.0.0.1") {
		t.Fatalf("the transport error leaked: %v", out)
	}
}
