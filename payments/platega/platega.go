package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
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

// platega is the Platega API: every request carries X-MerchantId and X-Secret. Without a
// payment method the payer picks one on Platega's page (POST /v2/transaction/process);
// with one, the invoice is made for that method (POST /transaction/process).
type platega struct {
	api      string
	hc       *http.Client
	manifest catalog.Manifest
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// 2 SBP QR, 3 ERIP, 11 card acquiring, 12 international, 13 crypto, 14 Sberpay.
	methodRe = regexp.MustCompile(`^(2|3|11|12|13|14)?$`)
)

func (p *platega) Info() adapter.Info {
	return adapter.Info{
		ID:           p.manifest.ID,
		Protocol:     p.manifest.Protocol,
		Version:      p.manifest.Version,
		Name:         p.manifest.Name,
		Currencies:   []string{"RUB"},
		Capabilities: []string{adapter.CapWebhook},
		Settings: []adapter.Setting{
			{Key: "merchant_id", Label: adapter.Text{"ru": "ID мерчанта", "en": "Merchant ID"}, Type: "string", Required: true, Pattern: uuidRe.String()},
			{Key: "secret", Label: adapter.Text{"ru": "Секретный ключ", "en": "Secret key"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
			{Key: "method", Label: adapter.Text{"ru": "Способ оплаты (пусто: выбирает плательщик)", "en": "Payment method (empty: the payer picks)"}, Type: "string", Pattern: methodRe.String()},
		},
		Help: adapter.Text{
			"ru": "ID мерчанта и секретный ключ — в личном кабинете Platega → Настройки. Там же в «Callback URLs» " +
				"укажите адрес уведомлений из панели. Способ оплаты: 2 СБП, 3 ЕРИП, 11 карты, 12 международная, " +
				"13 криптовалюта, 14 Sberpay; пусто — плательщик выберет сам.",
			"en": "The merchant ID and the secret key are in the Platega dashboard → Settings. Enter the panel's " +
				"notification URL under Callback URLs there. Payment method: 2 SBP, 3 ERIP, 11 cards, 12 international, " +
				"13 crypto, 14 Sberpay; empty lets the payer choose.",
		},
	}
}

// call sends one request with the credentials; they are never kept or logged.
func (p *platega) call(ctx context.Context, s adapter.Settings, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.api+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-MerchantId", s.String("merchant_id"))
	req.Header.Set("X-Secret", s.String("secret"))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, adapter.MaxBody))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return adapter.BadCredentials("Platega refused the merchant ID or the secret key")
	case resp.StatusCode == http.StatusNotFound:
		return adapter.NotFound("Platega has no such transaction")
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return adapter.ProviderUnavailable(fmt.Sprintf("Platega answered HTTP %d", resp.StatusCode))
	case resp.StatusCode/100 != 2:
		return adapter.Refused("platega_http_"+strconv.Itoa(resp.StatusCode), fmt.Sprintf("Platega refused the request (HTTP %d)", resp.StatusCode))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return adapter.ProviderUnavailable("Platega gave an unexpected answer")
	}
	return nil
}

// zeroID is a valid transaction id nobody owns: Platega has no "who am I" call, so Check
// asks for it. 404 means the credentials were accepted, 401 that they were not.
const zeroID = "00000000-0000-0000-0000-000000000000"

func (p *platega) Check(ctx context.Context, s adapter.Settings) error {
	err := p.call(ctx, s, http.MethodGet, "/transaction/"+zeroID, nil, nil)
	var e *adapter.Error
	if errors.As(err, &e) && e.Code == adapter.CodeNotFound {
		return nil
	}
	return err
}

// CreateInvoice makes the payment link. Platega has no idempotency keys and no lookup by
// our order, so a retried request can open a second link; only the one the panel stored
// is ever checked, and an unpaid extra expires on its own.
func (p *platega) CreateInvoice(ctx context.Context, r adapter.InvoiceRequest) (adapter.Invoice, error) {
	if r.ReturnURL == "" {
		return adapter.Invoice{}, adapter.BadRequest("Platega needs return_url")
	}
	desc := adapter.Truncate(strings.TrimSpace(r.Description), 255)
	if desc == "" {
		desc = "VPN"
	}
	body := map[string]any{
		"paymentDetails": map[string]any{"amount": json.Number(adapter.FormatMinor(r.Amount)), "currency": r.Currency},
		"description":    desc,
		"return":         r.ReturnURL,
		"failedUrl":      r.ReturnURL,
		"orderId":        r.IdempotencyKey,
		"payload":        r.IdempotencyKey,
	}
	path := "/v2/transaction/process"
	if m := r.Settings.String("method"); m != "" {
		n, err := strconv.Atoi(m)
		if err != nil {
			return adapter.Invoice{}, adapter.BadSettings("method has a wrong format")
		}
		path, body["paymentMethod"] = "/transaction/process", n
	}
	var res struct {
		ID       string `json:"transactionId"`
		URL      string `json:"url"`
		Redirect string `json:"redirect"`
	}
	if err := p.call(ctx, r.Settings, http.MethodPost, path, body, &res); err != nil {
		return adapter.Invoice{}, err
	}
	link := res.URL
	if link == "" {
		link = res.Redirect
	}
	if !uuidRe.MatchString(res.ID) || !httpsURL(link) {
		return adapter.Invoice{}, adapter.ProviderUnavailable("Platega gave no payment link")
	}
	return adapter.Invoice{ExternalID: res.ID, PayURL: link}, nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// Status: CONFIRMED → paid, CANCELED and CHARGEBACKED → canceled, the rest pending. The
// amount and currency are Platega's, for the panel to compare.
func (p *platega) Status(ctx context.Context, s adapter.Settings, externalID string) (adapter.Status, error) {
	if !uuidRe.MatchString(externalID) {
		return adapter.Status{}, adapter.BadRequest("external_id is not a Platega transaction id")
	}
	var res struct {
		Status  string `json:"status"`
		Details struct {
			Amount   json.Number `json:"amount"`
			Currency string      `json:"currency"`
		} `json:"paymentDetails"`
	}
	if err := p.call(ctx, s, http.MethodGet, "/transaction/"+externalID, nil, &res); err != nil {
		return adapter.Status{}, err
	}
	amount, ok := parseAmount(res.Details.Amount.String())
	if !ok || res.Details.Currency == "" {
		return adapter.Status{}, adapter.ProviderUnavailable("Platega gave a transaction without an amount")
	}
	st := adapter.StatusPending
	switch res.Status {
	case "CONFIRMED":
		st = adapter.StatusPaid
	case "CANCELED", "CHARGEBACKED":
		st = adapter.StatusCanceled
	}
	return adapter.Status{Status: st, Amount: amount, Currency: res.Details.Currency}, nil
}

// parseAmount reads Platega's amount, which comes with sixteen decimals
// (10.5000000000000000): past the cents only zeros may follow.
func parseAmount(s string) (int64, bool) {
	if whole, frac, ok := strings.Cut(s, "."); ok && len(frac) > 2 {
		if strings.Trim(frac[2:], "0") != "" {
			return 0, false
		}
		s = whole + "." + frac[:2]
	}
	return adapter.ParseMinor(s)
}

// Webhook checks X-MerchantId and X-Secret, which Platega puts on every callback, then
// names the transaction of a CONFIRMED one; other statuses are ignored.
func (p *platega) Webhook(_ context.Context, r adapter.WebhookRequest) (string, error) {
	if !same(r.Headers.Get("X-MerchantId"), r.Settings.String("merchant_id")) ||
		!same(r.Headers.Get("X-Secret"), r.Settings.String("secret")) {
		return "", adapter.BadRequest("the callback credentials do not match")
	}
	var cb struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if json.Unmarshal(r.Body, &cb) != nil || cb.Status == "" {
		return "", adapter.BadRequest("not a Platega callback")
	}
	if cb.Status != "CONFIRMED" {
		return "", nil
	}
	if !uuidRe.MatchString(cb.ID) {
		return "", adapter.BadRequest("a confirmed callback without a transaction")
	}
	return cb.ID, nil
}

// same compares in constant time (hashes first, so the length does not leak); an empty
// expected value never matches.
func same(got, want string) bool {
	if want == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
