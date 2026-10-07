package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

// invoiceTTL is how long an invoice can be paid, as the panel's built-in CryptoBot did.
const invoiceTTL = time.Hour

// cryptoBot is the Crypto Pay API (@CryptoBot): the app token goes in
// Crypto-Pay-API-Token. Invoices are in fiat; the payer picks the coin.
type cryptoBot struct {
	api, testAPI string
	hc           *http.Client
	manifest     catalog.Manifest
}

func (cb *cryptoBot) Info() adapter.Info {
	return adapter.Info{
		ID:           cb.manifest.ID,
		Protocol:     cb.manifest.Protocol,
		Version:      cb.manifest.Version,
		Name:         cb.manifest.Name,
		Currencies:   []string{"RUB", "USD", "EUR"},
		Capabilities: []string{adapter.CapWebhook},
		Settings: []adapter.Setting{
			{Key: "token", Label: adapter.Text{"ru": "Токен API", "en": "API token"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
			{Key: "testnet", Label: adapter.Text{"ru": "Тестовая сеть", "en": "Testnet"}, Type: "bool"},
		},
		Help: adapter.Text{
			"ru": "Токен — в @CryptoBot → Crypto Pay → Мои приложения → приложение → Токен API. " +
				"Там же в «Вебхуках» включите их и укажите адрес для уведомлений из панели. " +
				"Для проверки создайте приложение в @CryptoTestnetBot и включите «Тестовая сеть».",
			"en": "The token is in @CryptoBot → Crypto Pay → My Apps → the app → API Token. " +
				"Under Webhooks there, turn them on and enter the panel's notification URL. " +
				"To try it out, create an app in @CryptoTestnetBot and turn on Testnet.",
		},
	}
}

type cbInvoice struct {
	ID      int64      `json:"invoice_id"`
	Status  string     `json:"status"` // active | paid | expired
	Fiat    string     `json:"fiat"`
	Amount  flexNumber `json:"amount"` // a string in the docs, a number in some answers
	Payload string     `json:"payload"`
	BotURL  string     `json:"bot_invoice_url"`
}

// client is one app token for one request; it is never kept.
type client struct {
	base, token string
	hc          *http.Client
}

func (cb *cryptoBot) client(s adapter.Settings) client {
	base := cb.api
	if s.Bool("testnet") {
		base = cb.testAPI
	}
	return client{base: base, token: s.String("token"), hc: cb.hc}
}

func (c client) call(ctx context.Context, method string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/"+method, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Crypto-Pay-API-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, adapter.MaxBody))
	if err != nil {
		return err
	}
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  struct {
			Name string `json:"name"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return adapter.ProviderUnavailable(fmt.Sprintf("CryptoBot answered HTTP %d", resp.StatusCode))
		}
		return adapter.ProviderUnavailable("CryptoBot answered with something that is not JSON")
	}
	if !env.OK {
		return cbError(resp.StatusCode, env.Error.Name)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return adapter.ProviderUnavailable("CryptoBot gave an unexpected result")
	}
	return nil
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,40}$`)

// cbError maps Crypto Pay's errors ({"ok":false,"error":{"code":401,"name":"UNAUTHORIZED"}})
// to the protocol's codes.
func cbError(status int, name string) error {
	switch {
	case status == http.StatusUnauthorized || name == "UNAUTHORIZED":
		return adapter.BadCredentials("CryptoBot refused the API token")
	case status == http.StatusTooManyRequests || status >= 500:
		return adapter.ProviderUnavailable(fmt.Sprintf("CryptoBot answered HTTP %d", status))
	}
	if !nameRe.MatchString(name) {
		name = "error"
	}
	return adapter.Refused("cryptobot_"+strings.ToLower(name), fmt.Sprintf("CryptoBot refused the request (HTTP %d, %s)", status, name))
}

// Check asks for the app the token belongs to (getMe).
func (cb *cryptoBot) Check(ctx context.Context, s adapter.Settings) error {
	var me struct {
		AppID int64 `json:"app_id"`
	}
	return cb.client(s).call(ctx, "getMe", struct{}{}, &me)
}

// CreateInvoice opens a fiat invoice. Crypto Pay has no idempotency keys, so the key is
// the invoice payload, and an active invoice with that payload is returned instead of
// creating a second one.
func (cb *cryptoBot) CreateInvoice(ctx context.Context, r adapter.InvoiceRequest) (adapter.Invoice, error) {
	c := cb.client(r.Settings)
	if inv, ok, err := c.findActive(ctx, r.IdempotencyKey); err != nil || ok {
		return inv, err
	}
	body := map[string]any{
		"currency_type": "fiat",
		"fiat":          r.Currency,
		"amount":        adapter.FormatMinor(r.Amount),
		"payload":       r.IdempotencyKey,
		"expires_in":    int(invoiceTTL.Seconds()),
	}
	if r.Description != "" {
		body["description"] = adapter.Truncate(r.Description, 1024)
	}
	if r.ReturnURL != "" {
		body["paid_btn_name"], body["paid_btn_url"] = "callback", r.ReturnURL
	}
	var inv cbInvoice
	if err := c.call(ctx, "createInvoice", body, &inv); err != nil {
		return adapter.Invoice{}, err
	}
	if inv.ID == 0 || inv.BotURL == "" {
		return adapter.Invoice{}, adapter.ProviderUnavailable("CryptoBot gave no invoice link")
	}
	return adapter.Invoice{ExternalID: strconv.FormatInt(inv.ID, 10), PayURL: inv.BotURL}, nil
}

// findActive looks for an active invoice with this payload among the 100 latest: a
// retried request finds the invoice the first attempt created.
func (c client) findActive(ctx context.Context, payload string) (adapter.Invoice, bool, error) {
	var res struct {
		Items []cbInvoice `json:"items"`
	}
	if err := c.call(ctx, "getInvoices", map[string]any{"status": "active", "count": 100}, &res); err != nil {
		return adapter.Invoice{}, false, err
	}
	for _, inv := range res.Items {
		if inv.Payload == payload && inv.ID != 0 && inv.BotURL != "" {
			return adapter.Invoice{ExternalID: strconv.FormatInt(inv.ID, 10), PayURL: inv.BotURL}, true, nil
		}
	}
	return adapter.Invoice{}, false, nil
}

var invoiceIDRe = regexp.MustCompile(`^[0-9]{1,18}$`)

// Status: paid → paid, expired → canceled, active → pending. The amount and the fiat
// currency are CryptoBot's, for the panel to compare.
func (cb *cryptoBot) Status(ctx context.Context, s adapter.Settings, externalID string) (adapter.Status, error) {
	if !invoiceIDRe.MatchString(externalID) {
		return adapter.Status{}, adapter.BadRequest("external_id is not a CryptoBot invoice id")
	}
	var res struct {
		Items []cbInvoice `json:"items"`
	}
	if err := cb.client(s).call(ctx, "getInvoices", map[string]any{"invoice_ids": externalID}, &res); err != nil {
		return adapter.Status{}, err
	}
	for _, inv := range res.Items {
		if strconv.FormatInt(inv.ID, 10) != externalID {
			continue
		}
		amount, ok := adapter.ParseMinor(string(inv.Amount))
		if !ok || inv.Fiat == "" {
			return adapter.Status{}, adapter.ProviderUnavailable("CryptoBot gave an invoice without a fiat amount")
		}
		st := adapter.StatusPending
		switch inv.Status {
		case "paid":
			st = adapter.StatusPaid
		case "expired":
			st = adapter.StatusCanceled
		}
		return adapter.Status{Status: st, Amount: amount, Currency: inv.Fiat}, nil
	}
	return adapter.Status{}, adapter.NotFound("CryptoBot has no such invoice")
}

// Webhook checks crypto-pay-api-signature, then names the invoice of an invoice_paid
// update; other updates are ignored.
func (cb *cryptoBot) Webhook(_ context.Context, r adapter.WebhookRequest) (string, error) {
	if !validSignature(r.Settings.String("token"), r.Body, r.Headers.Get("Crypto-Pay-Api-Signature")) {
		return "", adapter.BadRequest("the signature does not match the API token")
	}
	var u struct {
		Type    string `json:"update_type"`
		Payload struct {
			ID int64 `json:"invoice_id"`
		} `json:"payload"`
	}
	if json.Unmarshal(r.Body, &u) != nil || u.Type == "" {
		return "", adapter.BadRequest("not a CryptoBot update")
	}
	if u.Type != "invoice_paid" {
		return "", nil
	}
	if u.Payload.ID <= 0 {
		return "", adapter.BadRequest("an invoice_paid update without an invoice")
	}
	return strconv.FormatInt(u.Payload.ID, 10), nil
}

// validSignature checks crypto-pay-api-signature: HMAC-SHA256 of the raw body with
// SHA-256 of the app token as the key, compared in constant time.
func validSignature(token string, body []byte, signature string) bool {
	if token == "" || signature == "" {
		return false
	}
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	key := sha256.Sum256([]byte(token))
	m := hmac.New(sha256.New, key[:])
	m.Write(body)
	return hmac.Equal(got, m.Sum(nil))
}

// flexNumber takes a JSON string or number: "199.00" and 199 both mean the same sum.
type flexNumber string

func (f *flexNumber) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexNumber(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexNumber(n.String())
	return nil
}
