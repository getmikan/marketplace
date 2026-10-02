package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

// rollyPay is the RollyPay API (https://docs.rollypay.io): X-API-Key and a fresh X-Nonce
// on every request. The order_id is the key of a payment: one order_id, one payment.
type rollyPay struct {
	api      string
	hc       *http.Client
	manifest catalog.Manifest
}

var (
	idRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	methodRe = regexp.MustCompile(`^(sbp|card|intl_card|crypto)?$`)
)

func (p *rollyPay) Info() adapter.Info {
	return adapter.Info{
		ID:           p.manifest.ID,
		Protocol:     p.manifest.Protocol,
		Version:      p.manifest.Version,
		Name:         p.manifest.Name,
		Currencies:   []string{"RUB"},
		Capabilities: []string{adapter.CapWebhook},
		Settings: []adapter.Setting{
			{Key: "api_key", Label: adapter.Text{"ru": "API-ключ кассы", "en": "Terminal API key"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
			{Key: "signing_secret", Label: adapter.Text{"ru": "Секрет подписи вебхуков", "en": "Webhook signing secret"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
			{Key: "method", Label: adapter.Text{"ru": "Способ оплаты (пусто: выбирает плательщик)", "en": "Payment method (empty: the payer picks)"}, Type: "string", Pattern: methodRe.String()},
			{Key: "test", Label: adapter.Text{"ru": "Тестовый режим", "en": "Sandbox"}, Type: "bool"},
		},
		Help: adapter.Text{
			"ru": "API-ключ и секрет подписи — в личном кабинете RollyPay → Настройки кассы. Там же задайте адрес " +
				"вебхуков (callback_url) из панели. Способ оплаты: sbp, card, intl_card, crypto; пусто — плательщик выберет сам. " +
				"«Тестовый режим» создаёт платежи в песочнице без реальных денег.",
			"en": "The API key and the signing secret are in the RollyPay dashboard → terminal settings. Set the panel's " +
				"notification URL there as callback_url. Payment method: sbp, card, intl_card, crypto; empty lets the payer choose. " +
				"Sandbox creates payments without real money.",
		},
	}
}

// call sends one request with the key and a fresh nonce; neither is kept or logged. A
// non-2xx answer comes back as *apiError for the caller to read, or mapped by fail.
func (p *rollyPay) call(ctx context.Context, s adapter.Settings, method, path string, query url.Values, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	u := p.api + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	req.Header.Set("X-API-Key", s.String("api_key"))
	req.Header.Set("X-Nonce", hex.EncodeToString(nonce))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if s.Bool("test") {
		req.Header.Set("X-Test-Mode", "true")
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, adapter.MaxBody))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fail(resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, adapter.ProviderUnavailable("RollyPay gave an unexpected answer")
		}
	}
	return resp.StatusCode, nil
}

// fail maps RollyPay's HTTP statuses ({"error": "..."}) to the protocol's codes. The
// text of the error is not passed on: it may repeat what was sent.
func fail(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return adapter.BadCredentials("RollyPay refused the API key")
	case status == http.StatusNotFound:
		return adapter.NotFound("RollyPay has no such payment")
	case status == http.StatusTooManyRequests || status >= 500:
		return adapter.ProviderUnavailable(fmt.Sprintf("RollyPay answered HTTP %d", status))
	}
	return adapter.Refused("rollypay_http_"+strconv.Itoa(status), fmt.Sprintf("RollyPay refused the request (HTTP %d)", status))
}

// Check reads the terminal linked to the API key. RollyPay's balance endpoint
// currently requires terminal_id even though the docs say the key is enough.
func (p *rollyPay) Check(ctx context.Context, s adapter.Settings) error {
	var terminal struct {
		ID string `json:"id"`
	}
	if _, err := p.call(ctx, s, http.MethodGet, "/terminals", nil, nil, &terminal); err != nil {
		return err
	}
	if terminal.ID == "" {
		return adapter.ProviderUnavailable("RollyPay gave no terminal ID")
	}
	return nil
}

type payment struct {
	ID       string      `json:"payment_id"`
	OrderID  string      `json:"order_id"`
	Status   string      `json:"status"`
	PayURL   string      `json:"pay_url"`
	Amount   json.Number `json:"amount"` // "1500.00"
	Currency string      `json:"payment_currency"`
}

// CreateInvoice opens a payment with order_id = the idempotency key. When RollyPay says
// the order already exists (409), the payment the first attempt made is looked up and
// returned instead of a second one.
func (p *rollyPay) CreateInvoice(ctx context.Context, r adapter.InvoiceRequest) (adapter.Invoice, error) {
	body := map[string]any{
		"amount":           adapter.FormatMinor(r.Amount),
		"payment_currency": r.Currency,
		"order_id":         r.IdempotencyKey,
	}
	if d := strings.TrimSpace(r.Description); d != "" {
		body["description"] = adapter.Truncate(d, 255)
	}
	if r.ReturnURL != "" {
		body["success_redirect_url"], body["fail_redirect_url"] = r.ReturnURL, r.ReturnURL
	}
	if m := r.Settings.String("method"); m != "" {
		body["payment_method"] = m
	}
	if r.Settings.Bool("test") {
		body["test"] = true
	}
	var pay payment
	status, err := p.call(ctx, r.Settings, http.MethodPost, "/payments", nil, body, &pay)
	if status == http.StatusConflict {
		return p.existing(ctx, r.Settings, r.IdempotencyKey)
	}
	if err != nil {
		return adapter.Invoice{}, err
	}
	return invoiceOf(pay)
}

func invoiceOf(pay payment) (adapter.Invoice, error) {
	if !idRe.MatchString(pay.ID) || !httpsURL(pay.PayURL) {
		return adapter.Invoice{}, adapter.ProviderUnavailable("RollyPay gave no payment link")
	}
	return adapter.Invoice{ExternalID: pay.ID, PayURL: pay.PayURL}, nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// existing finds the live payment of an order. The list answer is read loosely (a bare
// array, or an object holding one): the docs do not fix its shape.
func (p *rollyPay) existing(ctx context.Context, s adapter.Settings, orderID string) (adapter.Invoice, error) {
	var raw json.RawMessage
	if _, err := p.call(ctx, s, http.MethodGet, "/payments", url.Values{"order_id": {orderID}, "limit": {"5"}}, nil, &raw); err != nil {
		return adapter.Invoice{}, err
	}
	for _, pay := range paymentsIn(raw) {
		if pay.OrderID == orderID && (pay.Status == "created" || pay.Status == "processing" || pay.Status == "paid") {
			return invoiceOf(pay)
		}
	}
	return adapter.Invoice{}, adapter.Refused("rollypay_order_exists", "RollyPay already has a closed payment for this order")
}

func paymentsIn(raw json.RawMessage) []payment {
	var list []payment
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	for _, v := range obj {
		if json.Unmarshal(v, &list) == nil && len(list) > 0 {
			return list
		}
	}
	return nil
}

// Status: paid → paid; expired, canceled, chargeback and refunded → canceled; created
// and processing → pending. The amount and currency are RollyPay's, for the panel to
// compare.
func (p *rollyPay) Status(ctx context.Context, s adapter.Settings, externalID string) (adapter.Status, error) {
	if !idRe.MatchString(externalID) {
		return adapter.Status{}, adapter.BadRequest("external_id is not a RollyPay payment id")
	}
	var pay payment
	if _, err := p.call(ctx, s, http.MethodGet, "/payments/"+externalID, nil, nil, &pay); err != nil {
		return adapter.Status{}, err
	}
	amount, ok := parseRollyAmount(pay.Amount)
	if !ok || pay.Currency == "" {
		return adapter.Status{}, adapter.ProviderUnavailable("RollyPay gave a payment without an amount")
	}
	st := adapter.StatusPending
	switch pay.Status {
	case "paid":
		st = adapter.StatusPaid
	case "expired", "canceled", "chargeback", "refunded":
		st = adapter.StatusCanceled
	}
	return adapter.Status{Status: st, Amount: amount, Currency: pay.Currency}, nil
}

// RollyPay may serialize a RUB amount with eight decimal places. Accept only
// extra zeroes so a fractional kopeck can never be treated as paid in full.
func parseRollyAmount(n json.Number) (int64, bool) {
	s := n.String()
	if whole, frac, ok := strings.Cut(s, "."); ok {
		frac = strings.TrimRight(frac, "0")
		if frac == "" {
			s = whole
		} else {
			s = whole + "." + frac
		}
	}
	return adapter.ParseMinor(s)
}

// Webhook checks X-Signature: the hex HMAC-SHA256 of "<X-Timestamp>.<body>" keyed with
// the signing secret. payment.paid names the payment; other events are ignored (the
// panel asks Status anyway, which is what decides).
func (p *rollyPay) Webhook(_ context.Context, r adapter.WebhookRequest) (string, error) {
	if !validSignature(r.Settings.String("signing_secret"), r.Headers.Get("X-Timestamp"), r.Body, r.Headers.Get("X-Signature")) {
		return "", adapter.BadRequest("the signature does not match the signing secret")
	}
	var ev struct {
		Type      string `json:"event_type"`
		PaymentID string `json:"payment_id"`
	}
	if json.Unmarshal(r.Body, &ev) != nil || ev.Type == "" {
		return "", adapter.BadRequest("not a RollyPay event")
	}
	if ev.Type != "payment.paid" {
		return "", nil
	}
	if !idRe.MatchString(ev.PaymentID) {
		return "", adapter.BadRequest("a paid event without a payment")
	}
	return ev.PaymentID, nil
}

func validSignature(secret, timestamp string, body []byte, signature string) bool {
	if secret == "" || timestamp == "" || signature == "" {
		return false
	}
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}
