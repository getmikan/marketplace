package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	cbToken = "12345:AAcryptoTOKENvalue"
	token   = "adapter-token-for-tests"
)

// fakeCryptoBot answers like Crypto Pay with whatever the test put in invoices.
type fakeCryptoBot struct {
	mu       sync.Mutex
	invoices map[int64]*cbInvoice
	created  []map[string]any // bodies of createInvoice
	calls    int
	n        int64
}

func (f *fakeCryptoBot) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if r.Header.Get("Crypto-Pay-API-Token") != cbToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":401,"name":"UNAUTHORIZED"}}`))
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	var res any
	switch r.URL.Path {
	case "/getMe":
		res = map[string]any{"app_id": 1, "name": "mikan"}
	case "/createInvoice":
		f.created = append(f.created, in)
		f.n++
		inv := &cbInvoice{ID: f.n, Status: "active", Fiat: in["fiat"].(string), Amount: flexNumber(in["amount"].(string)),
			Payload: in["payload"].(string), BotURL: "https://t.me/CryptoBot?start=IV" + strconv.FormatInt(f.n, 10)}
		f.invoices[inv.ID] = inv
		res = inv
	case "/getInvoices":
		items := []*cbInvoice{}
		if ids, ok := in["invoice_ids"].(string); ok {
			id, _ := strconv.ParseInt(ids, 10, 64)
			if inv, ok := f.invoices[id]; ok {
				items = append(items, inv)
			}
		} else {
			for _, inv := range f.invoices {
				if inv.Status == in["status"] {
					items = append(items, inv)
				}
			}
		}
		res = map[string]any{"items": items}
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":404,"name":"METHOD_NOT_FOUND"}}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": res})
}

type env struct {
	t        *testing.T
	cb, test *fakeCryptoBot
	h        http.Handler
	logs     *bytes.Buffer
}

func newFake() *fakeCryptoBot { return &fakeCryptoBot{invoices: map[int64]*cbInvoice{}} }

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, cb: newFake(), test: newFake(), logs: &bytes.Buffer{}}
	prod, test := httptest.NewServer(e.cb), httptest.NewServer(e.test)
	t.Cleanup(prod.Close)
	t.Cleanup(test.Close)
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.h, err = adapter.NewHandler(&cryptoBot{api: prod.URL, testAPI: test.URL, hc: prod.Client(), manifest: m}, token,
		slog.New(slog.NewTextHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if strings.Contains(e.logs.String(), cbToken) {
			t.Error("the API token is in the log")
		}
	})
	return e
}

func (e *env) call(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	if body == nil {
		raw = nil
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

func settings() map[string]any { return map[string]any{"token": cbToken} }

func (e *env) invoice(key string, amount int64, currency string) string {
	e.t.Helper()
	code, out := e.call(http.MethodPost, "/v1/invoices", map[string]any{"settings": settings(), "payment_id": 4217, "idempotency_key": key,
		"amount": amount, "currency": currency, "description": "VPN · Месяц", "return_url": "https://panel.example.com/tg"})
	if code != http.StatusOK || !strings.HasPrefix(out["pay_url"].(string), "https://t.me/CryptoBot") {
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
	if code != http.StatusOK || out["id"] != "cryptobot" || out["protocol"] != 1.0 || out["version"] != manifestVersion(t) {
		t.Fatalf("info: %d %v", code, out)
	}
	if got, _ := json.Marshal(out["capabilities"]); string(got) != `["webhook"]` {
		t.Fatalf("capabilities: %s", got)
	}
	settings, _ := json.Marshal(out["settings"])
	if !strings.Contains(string(settings), `"key":"token"`) || !strings.Contains(string(settings), `"secret":true`) ||
		!strings.Contains(string(settings), `"key":"testnet"`) {
		t.Fatalf("settings: %s", settings)
	}
	// No refund capability, no refunds.
	code, out = e.call(http.MethodPost, "/v1/refund", map[string]any{"settings": map[string]any{"token": cbToken}, "external_id": "1", "amount": 100})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("good token: %d %v", code, out)
	}
	code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"token": "12345:AAwrong"}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadCredentials)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"token": "has space"}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"token": cbToken, "testnet": "yes"}})
	wantError(t, code, out, http.StatusUnprocessableEntity, adapter.CodeBadSettings)

	// testnet: the same call goes to the test API.
	prodCalls, testCalls := e.cb.calls, e.test.calls
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"token": cbToken, "testnet": true}}); code != http.StatusOK {
		t.Fatalf("testnet: %d %v", code, out)
	}
	if e.cb.calls != prodCalls || e.test.calls != testCalls+1 {
		t.Fatalf("testnet went to the main API: main %d→%d, test %d→%d", prodCalls, e.cb.calls, testCalls, e.test.calls)
	}
}

func TestCreateInvoice(t *testing.T) {
	e := newEnv(t)
	id := e.invoice("mikan-4217", 19900, "RUB")
	if len(e.cb.created) != 1 {
		t.Fatalf("created %d invoices", len(e.cb.created))
	}
	body, _ := json.Marshal(e.cb.created[0])
	want := `{"amount":"199.00","currency_type":"fiat","description":"VPN · Месяц","expires_in":3600,"fiat":"RUB",` +
		`"paid_btn_name":"callback","paid_btn_url":"https://panel.example.com/tg","payload":"mikan-4217"}`
	if string(body) != want {
		t.Fatalf("createInvoice body\n got %s\nwant %s", body, want)
	}
	// A retry with the same key finds the active invoice instead of creating another.
	if again := e.invoice("mikan-4217", 19900, "RUB"); again != id || len(e.cb.created) != 1 {
		t.Fatalf("retry: %s, %d invoices", again, len(e.cb.created))
	}
	usd := e.invoice("mikan-4218", 250, "USD")
	if usd == id || e.cb.created[1]["fiat"] != "USD" || e.cb.created[1]["amount"] != "2.50" {
		t.Fatalf("USD invoice: %v", e.cb.created[1])
	}
	code, out := e.call(http.MethodPost, "/v1/invoices", map[string]any{"settings": settings(), "payment_id": 1, "idempotency_key": "k", "amount": 0, "currency": "RUB"})
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	id := e.invoice("mikan-1", 19900, "RUB")
	n, _ := strconv.ParseInt(id, 10, 64)
	for cbStatus, want := range map[string]string{"active": "pending", "paid": "paid", "expired": "canceled"} {
		e.cb.invoices[n].Status = cbStatus
		code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": id})
		if code != http.StatusOK || out["status"] != want || out["amount"] != 19900.0 || out["currency"] != "RUB" {
			t.Fatalf("%s: %d %v", cbStatus, code, out)
		}
	}
	// Some answers carry the amount as a number.
	var inv cbInvoice
	if err := json.Unmarshal([]byte(`{"invoice_id":1,"status":"paid","fiat":"RUB","amount":199}`), &inv); err != nil || inv.Amount != "199" {
		t.Fatalf("number amount: %v %q", err, inv.Amount)
	}
	e.cb.invoices[n].Amount = "199"
	if _, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": id}); out["amount"] != 19900.0 {
		t.Fatalf("whole amount: %v", out)
	}
	code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "999"})
	wantError(t, code, out, http.StatusNotFound, adapter.CodeNotFound)
	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "1,2"})
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}

func sign(token string, body []byte) string {
	key := sha256.Sum256([]byte(token))
	m := hmac.New(sha256.New, key[:])
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func (e *env) webhook(headers map[string][]string, body string) (int, map[string]any) {
	return e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "remote_ip": "203.0.113.7",
		"headers": headers, "body": []byte(body)})
}

func TestWebhook(t *testing.T) {
	e := newEnv(t)
	paid := `{"update_id":1,"update_type":"invoice_paid","request_date":"2026-10-01T12:00:00.000Z","payload":{"invoice_id":7,"status":"paid","amount":"199.00","fiat":"RUB"}}`
	sig := sign(cbToken, []byte(paid))
	for _, name := range []string{"Crypto-Pay-Api-Signature", "crypto-pay-api-signature"} {
		if code, out := e.webhook(map[string][]string{name: {sig}}, paid); code != http.StatusOK || out["external_id"] != "7" {
			t.Fatalf("header %s: %d %v", name, code, out)
		}
	}
	for name, h := range map[string]map[string][]string{
		"no signature":     {},
		"another token":    {"Crypto-Pay-Api-Signature": {sign("999:AAother", []byte(paid))}},
		"not hex":          {"Crypto-Pay-Api-Signature": {"zz"}},
		"another body":     {"Crypto-Pay-Api-Signature": {sign(cbToken, []byte(paid+" "))}},
		"truncated digest": {"Crypto-Pay-Api-Signature": {sig[:32]}},
	} {
		code, out := e.webhook(h, paid)
		if code != http.StatusBadRequest || out["code"] != adapter.CodeBadRequest {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	other := `{"update_id":2,"update_type":"invoice_expired","payload":{"invoice_id":8}}`
	if code, out := e.webhook(map[string][]string{"Crypto-Pay-Api-Signature": {sign(cbToken, []byte(other))}}, other); code != http.StatusOK || len(out) != 0 {
		t.Fatalf("other update: %d %v", code, out)
	}
	junk := `[1,2]`
	code, out := e.webhook(map[string][]string{"Crypto-Pay-Api-Signature": {sign(cbToken, []byte(junk))}}, junk)
	wantError(t, code, out, http.StatusBadRequest, adapter.CodeBadRequest)
}
