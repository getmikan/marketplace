package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

// yooKassa is the YooKassa API v3: Basic auth with the shop id and the secret key.
// Test shops use the same API with their test keys, so there is no test switch.
type yooKassa struct {
	api      string
	hc       *http.Client
	manifest catalog.Manifest
}

func (y *yooKassa) Info() adapter.Info {
	return adapter.Info{
		ID:           y.manifest.ID,
		Protocol:     y.manifest.Protocol,
		Version:      y.manifest.Version,
		Name:         y.manifest.Name,
		Currencies:   []string{"RUB"},
		Capabilities: []string{adapter.CapWebhook, adapter.CapRefund},
		Settings: []adapter.Setting{
			{Key: "shop_id", Label: adapter.Text{"ru": "shopId", "en": "Shop ID"}, Type: "string", Required: true, Pattern: `^[0-9]{1,20}$`},
			{Key: "secret_key", Label: adapter.Text{"ru": "Секретный ключ", "en": "Secret key"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
		},
		Help: adapter.Text{
			"ru": "shopId и секретный ключ — в личном кабинете ЮKassa → Интеграция → Ключи API. " +
				"Адрес для уведомлений из панели укажите там же, в разделе HTTP-уведомления, с событиями payment.succeeded и payment.canceled.",
			"en": "The shop ID and the secret key are in the YooKassa dashboard → Integration → API keys. " +
				"Enter the panel's notification URL under Integration → HTTP notifications, with the events payment.succeeded and payment.canceled.",
		},
	}
}

type ykAmount struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

type ykPayment struct {
	ID           string   `json:"id"`
	Status       string   `json:"status"` // pending | waiting_for_capture | succeeded | canceled
	Amount       ykAmount `json:"amount"`
	Confirmation struct {
		URL string `json:"confirmation_url"`
	} `json:"confirmation"`
}

// client is one shop's credentials for one request; they are never kept.
type client struct {
	api, shopID, secret string
	hc                  *http.Client
}

func (y *yooKassa) client(s adapter.Settings) client {
	return client{api: y.api, shopID: s.String("shop_id"), secret: s.String("secret_key"), hc: y.hc}
}

func (c client) do(ctx context.Context, method, path, idem string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.shopID, c.secret)
	req.Header.Set("Content-Type", "application/json")
	if idem != "" {
		req.Header.Set("Idempotence-Key", idem)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, adapter.MaxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Code      string `json:"code"`
			Parameter string `json:"parameter"`
		}
		_ = json.Unmarshal(raw, &e)
		return ykError(resp.StatusCode, e.Code, e.Parameter)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return adapter.ProviderUnavailable("YooKassa answered with something that is not JSON")
	}
	return nil
}

var (
	codeRe  = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	paramRe = regexp.MustCompile(`^[A-Za-z0-9_.\[\]]{1,40}$`)
)

// ykError maps YooKassa's error answers to the protocol's codes.
func ykError(status int, code, param string) error {
	switch {
	case status == http.StatusUnauthorized:
		return adapter.BadCredentials("YooKassa refused the shop ID or the secret key")
	case status == http.StatusNotFound:
		return adapter.NotFound("YooKassa has no such payment")
	case status == http.StatusTooManyRequests || status >= 500:
		return adapter.ProviderUnavailable(fmt.Sprintf("YooKassa answered HTTP %d", status))
	}
	if !codeRe.MatchString(code) {
		code = "error"
	}
	msg := fmt.Sprintf("YooKassa refused the request (HTTP %d, %s)", status, code)
	// "invalid_request" alone says little: the field tells what the shop wants, e.g.
	// "receipt" when it has 54-FZ receipts switched on.
	if paramRe.MatchString(param) {
		msg += ", parameter " + param
	}
	return adapter.Refused("yookassa_"+code, msg)
}

// Check asks for the shop's own account (GET /me) with the keys.
func (y *yooKassa) Check(ctx context.Context, s adapter.Settings) error {
	var me struct {
		AccountID string `json:"account_id"`
	}
	return y.client(s).do(ctx, http.MethodGet, "/me", "", nil, &me)
}

// CreateInvoice opens a payment with a redirect to YooKassa's page. The idempotency key
// goes to YooKassa as Idempotence-Key: a retry returns the same payment.
func (y *yooKassa) CreateInvoice(ctx context.Context, r adapter.InvoiceRequest) (adapter.Invoice, error) {
	if r.ReturnURL == "" {
		return adapter.Invoice{}, adapter.BadRequest("return_url is required by YooKassa")
	}
	body := map[string]any{
		"amount":       ykAmount{Value: adapter.FormatMinor(r.Amount), Currency: r.Currency},
		"capture":      true,
		"confirmation": map[string]string{"type": "redirect", "return_url": r.ReturnURL},
		"metadata":     map[string]string{"mikan_payment_id": strconv.FormatInt(r.PaymentID, 10)},
	}
	if r.Description != "" {
		body["description"] = adapter.Truncate(r.Description, 128)
	}
	var p ykPayment
	if err := y.client(r.Settings).do(ctx, http.MethodPost, "/payments", r.IdempotencyKey, body, &p); err != nil {
		return adapter.Invoice{}, err
	}
	if p.ID == "" || p.Confirmation.URL == "" {
		return adapter.Invoice{}, adapter.ProviderUnavailable("YooKassa gave no payment link")
	}
	return adapter.Invoice{ExternalID: p.ID, PayURL: p.Confirmation.URL}, nil
}

var paymentIDRe = regexp.MustCompile(`^[0-9A-Za-z-]{1,64}$`)

func (c client) payment(ctx context.Context, id string) (ykPayment, error) {
	var p ykPayment
	if !paymentIDRe.MatchString(id) {
		return p, adapter.BadRequest("external_id is not a YooKassa payment id")
	}
	if err := c.do(ctx, http.MethodGet, "/payments/"+id, "", nil, &p); err != nil {
		return p, err
	}
	if p.ID != id {
		return p, adapter.ProviderUnavailable("YooKassa answered about another payment")
	}
	return p, nil
}

// Status: succeeded → paid, canceled → canceled, anything else (pending,
// waiting_for_capture) → pending. The amount is YooKassa's, for the panel to compare.
func (y *yooKassa) Status(ctx context.Context, s adapter.Settings, externalID string) (adapter.Status, error) {
	p, err := y.client(s).payment(ctx, externalID)
	if err != nil {
		return adapter.Status{}, err
	}
	amount, ok := adapter.ParseMinor(p.Amount.Value)
	if !ok || p.Amount.Currency == "" {
		return adapter.Status{}, adapter.ProviderUnavailable("YooKassa gave a payment without a valid amount")
	}
	st := adapter.StatusPending
	switch p.Status {
	case "succeeded":
		st = adapter.StatusPaid
	case "canceled":
		st = adapter.StatusCanceled
	}
	return adapter.Status{Status: st, Amount: amount, Currency: p.Amount.Currency}, nil
}

// Webhook accepts notifications only from YooKassa's addresses; YooKassa does not sign
// them. Payment events name the payment, the rest (refunds) is ignored.
func (y *yooKassa) Webhook(_ context.Context, r adapter.WebhookRequest) (string, error) {
	if !fromYooKassa(r.RemoteIP) {
		return "", adapter.BadRequest("the notification does not come from YooKassa's addresses")
	}
	var n struct {
		Event  string `json:"event"`
		Object struct {
			ID string `json:"id"`
		} `json:"object"`
	}
	if json.Unmarshal(r.Body, &n) != nil || n.Event == "" || n.Object.ID == "" {
		return "", adapter.BadRequest("not a YooKassa notification")
	}
	if !strings.HasPrefix(n.Event, "payment.") {
		return "", nil
	}
	return n.Object.ID, nil
}

// Refund returns amount of the payment in the payment's currency. The idempotence key
// comes from the payment and the amount, so a retried request does not refund twice.
func (y *yooKassa) Refund(ctx context.Context, s adapter.Settings, externalID string, amount int64) error {
	c := y.client(s)
	p, err := c.payment(ctx, externalID)
	if err != nil {
		return err
	}
	var rf struct {
		ID     string `json:"id"`
		Status string `json:"status"` // pending | succeeded | canceled
	}
	body := map[string]any{"payment_id": p.ID, "amount": ykAmount{Value: adapter.FormatMinor(amount), Currency: p.Amount.Currency}}
	if err := c.do(ctx, http.MethodPost, "/refunds", refundKey(p.ID, amount), body, &rf); err != nil {
		return err
	}
	if rf.Status == "canceled" {
		return adapter.Refused("yookassa_refund_canceled", "YooKassa canceled the refund")
	}
	return nil
}

func refundKey(paymentID string, amount int64) string {
	sum := sha256.Sum256([]byte(paymentID + ":" + strconv.FormatInt(amount, 10)))
	return "mikan-refund-" + hex.EncodeToString(sum[:16])
}

// yooKassaNets are where YooKassa sends notifications from
// (https://yookassa.ru/developers/using-api/webhooks#ip).
var yooKassaNets = []netip.Prefix{
	netip.MustParsePrefix("185.71.76.0/27"),
	netip.MustParsePrefix("185.71.77.0/27"),
	netip.MustParsePrefix("77.75.153.0/25"),
	netip.MustParsePrefix("77.75.156.11/32"),
	netip.MustParsePrefix("77.75.156.35/32"),
	netip.MustParsePrefix("77.75.154.128/25"),
	netip.MustParsePrefix("2a02:5180::/32"),
}

func fromYooKassa(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, n := range yooKassaNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}
