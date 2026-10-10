package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

const (
	apiToken = "cardlink-api-token-value"
	shopID   = "9f1c4b2a-0e77-4a51-9d3e-2b5b8c0a1234"
	token    = "adapter-token-for-tests"
	billID   = "GkLWvKx3"
)

// fakeCardlink answers like Cardlink for one bill the test sets up.
type fakeCardlink struct {
	mu sync.Mutex
	// balancePath is where this merchant's balance lives: the reference gives it both
	// ways, so the default exercises the fallback.
	balancePath string
	status      string
	amount      json.Number
	currency    string
	active      *bool
	search      []map[string]any // what /bill/search answers, inside a paginator
	paths       []string
	created     []url.Values
}

func (f *fakeCardlink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+apiToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == f.balancePath:
		_ = json.NewEncoder(w).Encode(map[string]any{"balances": []any{map[string]any{"currency": "RUB", "balance_available": "10.00"}}})
	case r.Method == http.MethodGet && r.URL.Path == "/bill/search":
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true,
			"data": map[string]any{"current_page": 1, "data": f.search}})
	case r.Method == http.MethodPost && r.URL.Path == "/bill/create":
		_ = r.ParseForm()
		f.created = append(f.created, r.PostForm)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "bill_id": billID,
			"link_url": "https://cardlink.link/link/" + billID, "link_page_url": "https://cardlink.link/pay/" + billID})
	case r.Method == http.MethodGet && r.URL.Path == "/bill/status":
		if r.URL.Query().Get("id") != billID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b := map[string]any{"id": billID, "order_id": "mikan-4217", "status": f.status, "amount": f.amount, "currency_in": f.currency}
		if f.active != nil {
			b["active"] = *f.active
		}
		_ = json.NewEncoder(w).Encode(b)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeCardlink) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeCardlink) bills() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.created...)
}

type env struct {
	t    *testing.T
	fake *fakeCardlink
	h    http.Handler
	logs *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, logs: &bytes.Buffer{},
		fake: &fakeCardlink{balancePath: "/merchant/balance", status: "NEW", amount: "199.00", currency: "RUB"}}
	srv := httptest.NewServer(e.fake)
	t.Cleanup(srv.Close)
	m, err := catalog.ParseManifest(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	e.h, err = adapter.NewHandler(&cardlink{api: srv.URL, hc: srv.Client(), manifest: m}, token, slog.New(slog.NewTextHandler(e.logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if strings.Contains(e.logs.String(), apiToken) {
			t.Error("the API token is in the log")
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

func settings(extra ...any) map[string]any {
	s := map[string]any{"api_token": apiToken, "shop_id": shopID}
	if len(extra) == 2 {
		s[extra[0].(string)] = extra[1]
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
		"description": "VPN · Месяц", "return_url": "https://panel.example.com/tg",
		"webhook_url": "https://panel.example.com/s9Hj/pay/addon/cardlink/tok"}
}

func TestInfo(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodGet, "/v1/info", nil)
	if code != http.StatusOK || out["id"] != "cardlink" || out["protocol"] != 1.0 {
		t.Fatalf("info: %d %v", code, out)
	}
	if got, _ := json.Marshal(out["capabilities"]); string(got) != `["webhook"]` {
		t.Fatalf("capabilities: %s", got)
	}
	if got, _ := json.Marshal(out["currencies"]); string(got) != `["RUB","USD","EUR"]` {
		t.Fatalf("currencies: %s", got)
	}
	secrets := map[string]bool{}
	for _, f := range out["settings"].([]any) {
		m := f.(map[string]any)
		secrets[m["key"].(string)] = m["secret"].(bool)
	}
	if !secrets["api_token"] || secrets["shop_id"] || secrets["payment_method"] {
		t.Fatalf("secret flags: %v", secrets)
	}
}

// The refund endpoint is not served: Cardlink opens refunds only on a support request.
func TestRefundIsNotServed(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/refund", map[string]any{"settings": settings(), "external_id": billID, "amount": 19900})
	wantError(t, code, out, http.StatusNotFound, "not_found")
}

func TestCheck(t *testing.T) {
	e := newEnv(t)
	// The balance under the other path of the reference: the first call 404s, the second
	// one answers.
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK {
		t.Fatalf("check: %d %v", code, out)
	}
	if got := e.fake.calls(); len(got) != 2 || got[0] != "GET /balance" || got[1] != "GET /merchant/balance" {
		t.Fatalf("calls: %v", got)
	}

	e = newEnv(t)
	e.fake.balancePath = "/balance"
	if code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()}); code != http.StatusOK {
		t.Fatalf("check: %d %v", code, out)
	}
	if got := e.fake.calls(); len(got) != 1 {
		t.Fatalf("the balance was asked for twice: %v", got)
	}

	e = newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings("api_token", "wrong-token")})
	wantError(t, code, out, http.StatusUnprocessableEntity, "bad_credentials")

	e = newEnv(t)
	e.fake.balancePath = "/nowhere"
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": settings()})
	wantError(t, code, out, http.StatusBadGateway, "provider_unavailable")

	e = newEnv(t)
	code, out = e.call(http.MethodPost, "/v1/check", map[string]any{"settings": map[string]any{"api_token": apiToken, "shop_id": "no spaces allowed"}})
	wantError(t, code, out, http.StatusUnprocessableEntity, "bad_settings")
}

func TestInvoiceCreatesTheBill(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings("payment_method", "SBP")))
	if code != http.StatusOK || out["external_id"] != billID || out["pay_url"] != "https://cardlink.link/pay/"+billID {
		t.Fatalf("invoice: %d %v", code, out)
	}
	bills := e.fake.bills()
	if len(bills) != 1 {
		t.Fatalf("bills created: %d", len(bills))
	}
	f := bills[0]
	for k, want := range map[string]string{
		"amount": "199.00", "shop_id": shopID, "order_id": "mikan-4217", "currency_in": "RUB", "type": "normal",
		"ttl": "86400", "description": "VPN · Месяц", "success_url": "https://panel.example.com/tg",
		"fail_url": "https://panel.example.com/tg", "return_url": "https://panel.example.com/tg", "payment_method": "SBP",
	} {
		if f.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, f.Get(k), want)
		}
	}
	// The fee is the merchant's unless the admin says otherwise.
	if f.Has("payer_pays_commission") {
		t.Errorf("payer_pays_commission = %q, want it unset", f.Get("payer_pays_commission"))
	}
	// The bills of the key are looked up before a new one is made.
	if got := e.fake.calls(); len(got) != 2 || got[0] != "GET /bill/search" || got[1] != "POST /bill/create" {
		t.Fatalf("calls: %v", got)
	}

	e = newEnv(t)
	if code, out = e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings("payer_pays_commission", true))); code != http.StatusOK {
		t.Fatalf("invoice: %d %v", code, out)
	}
	if got := e.fake.bills()[0].Get("payer_pays_commission"); got != "1" {
		t.Fatalf("payer_pays_commission = %q", got)
	}
}

// One idempotency key, one bill: the second call gives back the bill the first one made.
func TestInvoiceReusesTheBillOfTheKey(t *testing.T) {
	e := newEnv(t)
	e.fake.search = []map[string]any{{"id": billID, "order_id": "mikan-4217", "status": "NEW", "active": true,
		"amount": "199.00", "currency_in": "RUB", "link_page_url": "https://cardlink.link/pay/" + billID}}
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	if code != http.StatusOK || out["external_id"] != billID {
		t.Fatalf("invoice: %d %v", code, out)
	}
	if got := e.fake.bills(); len(got) != 0 {
		t.Fatalf("a second bill was created: %v", got)
	}
}

// A bill of this key that Cardlink gives no link to is refused, not made twice.
func TestInvoiceRefusesABillWithoutALink(t *testing.T) {
	e := newEnv(t)
	e.fake.search = []map[string]any{{"id": billID, "order_id": "mikan-4217", "status": "PROCESS", "active": true}}
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	wantError(t, code, out, http.StatusUnprocessableEntity, "cardlink_bill_exists")
	if got := e.fake.bills(); len(got) != 0 {
		t.Fatalf("a second bill was created: %v", got)
	}
}

// A bill of this key that can no longer be paid does not stand in the way of a new one.
func TestInvoiceIgnoresADeadBill(t *testing.T) {
	e := newEnv(t)
	e.fake.search = []map[string]any{{"id": "oldBill1", "order_id": "mikan-4217", "status": "FAIL", "active": false}}
	code, out := e.call(http.MethodPost, "/v1/invoices", invoiceBody(settings()))
	if code != http.StatusOK || out["external_id"] != billID {
		t.Fatalf("invoice: %d %v", code, out)
	}
	if got := e.fake.bills(); len(got) != 1 {
		t.Fatalf("bills created: %d", len(got))
	}
}

func TestStatus(t *testing.T) {
	no, yes := false, true
	for _, c := range []struct {
		status string
		active *bool
		amount json.Number
		want   string
		minor  float64
	}{
		{status: "SUCCESS", amount: "199.00", want: "paid", minor: 19900},
		{status: "OVERPAID", amount: "199.00", want: "paid", minor: 19900},
		{status: "NEW", amount: "199.00", want: "pending", minor: 19900},
		{status: "PROCESS", active: &yes, amount: "199", want: "pending", minor: 19900},
		// Less than the bill arrived: not paid, the admin settles it in the dashboard.
		{status: "UNDERPAID", amount: "199.00", want: "pending", minor: 19900},
		{status: "FAIL", amount: "199.00", want: "canceled", minor: 19900},
		// Its time ran out: it can no longer be paid.
		{status: "NEW", active: &no, amount: "199.00", want: "canceled", minor: 19900},
		// Cardlink may write the sum with more decimals than a kopeck.
		{status: "SUCCESS", amount: "199.000000", want: "paid", minor: 19900},
	} {
		e := newEnv(t)
		e.fake.status, e.fake.amount, e.fake.active = c.status, c.amount, c.active
		code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": billID})
		if code != http.StatusOK || out["status"] != c.want || out["amount"] != c.minor || out["currency"] != "RUB" {
			t.Fatalf("%s/%v: %d %v, want %s %v", c.status, c.active, code, out, c.want, c.minor)
		}
	}
}

func TestStatusOfAnUnknownBill(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "noSuchBill"})
	wantError(t, code, out, http.StatusNotFound, "not_found")

	code, out = e.call(http.MethodPost, "/v1/status", map[string]any{"settings": settings(), "external_id": "../../balance"})
	wantError(t, code, out, http.StatusBadRequest, "bad_request")
}

// postback is a payment notification as Cardlink sends it, signed with the API token.
func postback(sum, inv, bill, signWith string) string {
	sig := md5.Sum([]byte(sum + ":" + inv + ":" + signWith))
	return url.Values{"InvId": {inv}, "OutSum": {sum}, "TrsId": {bill}, "Status": {"SUCCESS"},
		"CurrencyIn": {"RUB"}, "SignatureValue": {strings.ToUpper(hex.EncodeToString(sig[:]))}}.Encode()
}

func TestWebhook(t *testing.T) {
	e := newEnv(t)
	code, out := e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(),
		"remote_ip": "185.71.76.10", "body": []byte(postback("199.00", "mikan-4217", billID, apiToken))})
	if code != http.StatusOK || out["external_id"] != billID {
		t.Fatalf("webhook: %d %v", code, out)
	}

	// Signed with something else: a forgery.
	code, out = e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(),
		"body": []byte(postback("199.00", "mikan-4217", billID, "another-token"))})
	wantError(t, code, out, http.StatusBadRequest, "bad_request")

	// The sum is not the signed one: the signature no longer matches.
	code, out = e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(),
		"body": []byte(strings.Replace(postback("199.00", "mikan-4217", billID, apiToken), "OutSum=199.00", "OutSum=1.00", 1))})
	wantError(t, code, out, http.StatusBadRequest, "bad_request")

	// A refund postback: not the panel's business, and no bill of ours is named.
	refund := url.Values{"Id": {"42"}, "Amount": {"199.00"}, "Currency": {"RUB"}, "Status": {"SUCCESS"},
		"BillId": {billID}, "PaymentId": {"77"}, "SignatureValue": {"deadbeef"}}.Encode()
	code, out = e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "body": []byte(refund)})
	if code != http.StatusOK || len(out) != 0 {
		t.Fatalf("the refund postback was not ignored: %d %v", code, out)
	}

	// Not a form at all.
	code, out = e.call(http.MethodPost, "/v1/webhook", map[string]any{"settings": settings(), "body": []byte("OutSum=%zz")})
	wantError(t, code, out, http.StatusBadRequest, "bad_request")
}
