package main

import (
	"cmp"
	"context"
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/getmikan/marketplace/internal/adapter"
	"github.com/getmikan/marketplace/internal/catalog"
)

// cardlink is the Cardlink API (https://cardlink.link/reference/api): one Bearer token per
// merchant, form-encoded requests, JSON answers. A bill is an invoice; its order_id is our
// idempotency key and comes back in the postback as InvId, its id is the external id.
type cardlink struct {
	api      string
	hc       *http.Client
	manifest catalog.Manifest
}

// billTTL is how long a bill can be paid. The panel drops an unpaid invoice after a day,
// so a longer-lived bill would only collect late payments.
const billTTL = 24 * 60 * 60

var (
	// billRe is a bill id as it goes into a query string.
	billRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	shopRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	methodRe = regexp.MustCompile(`^(BANK_CARD|SBP)?$`)
)

func (p *cardlink) Info() adapter.Info {
	return adapter.Info{
		ID:           p.manifest.ID,
		Protocol:     p.manifest.Protocol,
		Version:      p.manifest.Version,
		Name:         p.manifest.Name,
		Currencies:   []string{"RUB", "USD", "EUR"},
		Capabilities: []string{adapter.CapWebhook},
		Settings: []adapter.Setting{
			{Key: "api_token", Label: adapter.Text{"ru": "Токен API", "en": "API token"}, Type: "string", Secret: true, Required: true, Pattern: `^[!-~]{1,200}$`},
			{Key: "shop_id", Label: adapter.Text{"ru": "ID магазина", "en": "Shop ID"}, Type: "string", Required: true, Pattern: shopRe.String()},
			{Key: "payment_method", Label: adapter.Text{"ru": "Способ оплаты (пусто: выбирает плательщик)", "en": "Payment method (empty: the payer picks)"}, Type: "string", Pattern: methodRe.String()},
			{Key: "payer_pays_commission", Label: adapter.Text{"ru": "Комиссию платит плательщик", "en": "The payer pays the fee"}, Type: "bool"},
		},
		Help: adapter.Text{
			"ru": "Токен — в кабинете Cardlink → Интеграции → API, ID магазина — на странице магазина. Там же, в магазине, " +
				"впишите адрес уведомлений из панели в поле Result URL, а домен магазина укажите тот же, что у панели: иначе " +
				"Cardlink не вернёт плательщика назад. Способ оплаты: BANK_CARD или SBP; пусто — плательщик выберет сам. " +
				"Возвраты этот способ оплаты не делает: Cardlink открывает их по заявке в поддержку, возвращайте в его кабинете.",
			"en": "The token is in the Cardlink dashboard → Integrations → API, the shop id on the shop's page. Put the panel's " +
				"notification URL into the shop's Result URL there, and give the shop the panel's own domain: Cardlink will not " +
				"send the payer back otherwise. Payment method: BANK_CARD or SBP; empty lets the payer choose. This method does " +
				"not refund: Cardlink opens refunds on a support request, so refund in its dashboard.",
		},
	}
}

// call sends one request with the merchant's token, which is used for this request only
// and never stored or logged. A GET takes form as its query, a POST as its body, the way
// Cardlink wants it. A non-2xx answer comes back mapped by fail, with its status, so the
// caller can tell "no such bill" from a refusal.
func (p *cardlink) call(ctx context.Context, s adapter.Settings, method, path string, form url.Values, out any) (int, error) {
	u := p.api + path
	var body io.Reader
	if method == http.MethodGet {
		if len(form) > 0 {
			u += "?" + form.Encode()
		}
	} else {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.String("api_token"))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
			return resp.StatusCode, adapter.ProviderUnavailable("Cardlink gave an unexpected answer")
		}
	}
	return resp.StatusCode, nil
}

// fail maps Cardlink's HTTP statuses to the protocol's codes. Its own message is not
// passed on: it may repeat what was sent.
func fail(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return adapter.BadCredentials("Cardlink refused the API token")
	case status == http.StatusNotFound:
		return adapter.NotFound("Cardlink has no such bill")
	case status == http.StatusTooManyRequests || status >= 500:
		return adapter.ProviderUnavailable(fmt.Sprintf("Cardlink answered HTTP %d", status))
	}
	return adapter.Refused("cardlink_http_"+strconv.Itoa(status), fmt.Sprintf("Cardlink refused the request (HTTP %d)", status))
}

// Check reads the merchant's balances: the shortest call the token alone can make. The
// reference gives that path both ways, so the other one is tried when the first is not
// there. The shop id cannot be checked this cheaply; a wrong one shows up as a payment
// form without the panel's return and notification URLs.
func (p *cardlink) Check(ctx context.Context, s adapter.Settings) error {
	status, err := p.call(ctx, s, http.MethodGet, "/balance", nil, nil)
	if status == http.StatusNotFound {
		status, err = p.call(ctx, s, http.MethodGet, "/merchant/balance", nil, nil)
	}
	if status == http.StatusNotFound {
		return adapter.ProviderUnavailable("Cardlink has no balance endpoint to check the token with")
	}
	return err
}

// bill is what Cardlink answers about an invoice. Creating one answers with bill_id and
// the two links, asking about one answers with id, its status and its amount.
type bill struct {
	ID       string      `json:"id"`
	BillID   string      `json:"bill_id"`
	OrderID  string      `json:"order_id"`
	Status   string      `json:"status"`
	Amount   json.Number `json:"amount"`
	Currency string      `json:"currency_in"`
	Active   *bool       `json:"active"`
	LinkPage string      `json:"link_page_url"`
	LinkURL  string      `json:"link_url"`
}

func (b bill) id() string { return cmp.Or(b.BillID, b.ID) }

// payURL is where the payer goes: the payment page, or the QR page when that is all there
// is. link_url alone is a page with the QR code of the same bill.
func (b bill) payURL() string { return cmp.Or(b.LinkPage, b.LinkURL) }

// state tells what the panel's three statuses mean for a bill. UNDERPAID is pending on
// purpose: money arrived, but less than the bill, and the amount Cardlink gives is the
// bill's own, so calling it paid would say more arrived than did. The admin settles those
// in the Cardlink dashboard.
func (b bill) state() string {
	switch strings.ToUpper(b.Status) {
	case "SUCCESS", "OVERPAID":
		return adapter.StatusPaid
	case "FAIL":
		return adapter.StatusCanceled
	}
	if b.Active != nil && !*b.Active {
		// Its time ran out or the merchant switched it off: it can no longer be paid.
		return adapter.StatusCanceled
	}
	return adapter.StatusPending
}

// CreateInvoice opens a bill whose order_id is the idempotency key. Cardlink has no
// idempotency key of its own and does not keep order ids unique, so the bills of that
// order are looked up first and the one an earlier call made is given back instead of a
// second one (PROTOCOL.md).
func (p *cardlink) CreateInvoice(ctx context.Context, r adapter.InvoiceRequest) (adapter.Invoice, error) {
	inv, found, err := p.existing(ctx, r.Settings, r.IdempotencyKey)
	if err != nil || found {
		return inv, err
	}
	form := url.Values{
		"amount":      {adapter.FormatMinor(r.Amount)},
		"shop_id":     {r.Settings.String("shop_id")},
		"order_id":    {r.IdempotencyKey},
		"currency_in": {r.Currency},
		"type":        {"normal"},
		"ttl":         {strconv.Itoa(billTTL)},
	}
	if d := strings.TrimSpace(r.Description); d != "" {
		form.Set("description", adapter.Truncate(d, 255))
	}
	if r.ReturnURL != "" {
		// Cardlink posts the payer's browser to these; the panel is told by the postback.
		form.Set("success_url", r.ReturnURL)
		form.Set("fail_url", r.ReturnURL)
		form.Set("return_url", r.ReturnURL)
	}
	if m := r.Settings.String("payment_method"); m != "" {
		form.Set("payment_method", m)
	}
	if r.Settings.Bool("payer_pays_commission") {
		form.Set("payer_pays_commission", "1")
	}
	var created bill
	if _, err := p.call(ctx, r.Settings, http.MethodPost, "/bill/create", form, &created); err != nil {
		return adapter.Invoice{}, err
	}
	return invoiceOf(created)
}

func invoiceOf(b bill) (adapter.Invoice, error) {
	if !billRe.MatchString(b.id()) || !httpsURL(b.payURL()) {
		return adapter.Invoice{}, adapter.ProviderUnavailable("Cardlink gave no payment link")
	}
	return adapter.Invoice{ExternalID: b.id(), PayURL: b.payURL()}, nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// existing finds the bill an earlier call with this idempotency key already made. found is
// false when there is none and a new bill is to be made. A bill that is there but gives no
// payment link is refused rather than made twice: the buyer's money must not go to a second
// bill of one invoice.
func (p *cardlink) existing(ctx context.Context, s adapter.Settings, orderID string) (adapter.Invoice, bool, error) {
	form := url.Values{"order_id": {orderID}, "per_page": {"10"}}
	if shop := s.String("shop_id"); shop != "" {
		form.Set("shop_id", shop)
	}
	var raw json.RawMessage
	status, err := p.call(ctx, s, http.MethodGet, "/bill/search", form, &raw)
	if err != nil {
		if status == http.StatusNotFound {
			return adapter.Invoice{}, false, nil // nothing of that order yet
		}
		return adapter.Invoice{}, false, err
	}
	for _, b := range billsIn(raw, 0) {
		if b.OrderID != orderID || b.state() == adapter.StatusCanceled {
			continue
		}
		inv, err := invoiceOf(b)
		if err != nil {
			return adapter.Invoice{}, true, adapter.Refused("cardlink_bill_exists",
				"Cardlink already has a bill for this payment, and gave no link to it")
		}
		return inv, true, nil
	}
	return adapter.Invoice{}, false, nil
}

// billsIn pulls the bills out of a search answer. The reference does not fix its shape (a
// bare array, an object holding one, a paginator holding that), so the first array that
// reads as bills with ids wins, "data" before the rest and the rest in order, so that two
// arrays cannot make it answer differently each time.
func billsIn(raw json.RawMessage, depth int) []bill {
	if depth > 4 {
		return nil
	}
	var list []bill
	if json.Unmarshal(raw, &list) == nil {
		if slices.ContainsFunc(list, func(b bill) bool { return b.id() != "" || b.OrderID != "" }) {
			return list
		}
		return nil
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		if k != "data" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	if _, ok := obj["data"]; ok {
		keys = append([]string{"data"}, keys...)
	}
	for _, k := range keys {
		if got := billsIn(obj[k], depth+1); len(got) > 0 {
			return got
		}
	}
	return nil
}

// Status asks about one bill. The amount and the currency are Cardlink's own, for the
// panel to compare with the payment it created.
func (p *cardlink) Status(ctx context.Context, s adapter.Settings, externalID string) (adapter.Status, error) {
	if !billRe.MatchString(externalID) {
		return adapter.Status{}, adapter.BadRequest("external_id is not a Cardlink bill id")
	}
	var b bill
	if _, err := p.call(ctx, s, http.MethodGet, "/bill/status", url.Values{"id": {externalID}}, &b); err != nil {
		return adapter.Status{}, err
	}
	amount, ok := parseAmount(b.Amount)
	if !ok || b.Currency == "" {
		return adapter.Status{}, adapter.ProviderUnavailable("Cardlink gave a bill without an amount")
	}
	return adapter.Status{Status: b.state(), Amount: amount, Currency: strings.ToUpper(b.Currency)}, nil
}

// parseAmount reads a bill's sum. Cardlink may write it with more than two decimal
// places; only extra zeroes are accepted, so a fractional kopeck can never be taken for
// the whole sum.
func parseAmount(n json.Number) (int64, bool) {
	s := strings.TrimSpace(n.String())
	if whole, frac, ok := strings.Cut(s, "."); ok {
		if frac = strings.TrimRight(frac, "0"); frac == "" {
			s = whole
		} else {
			s = whole + "." + frac
		}
	}
	return adapter.ParseMinor(s)
}

// Webhook reads Cardlink's postback: form-encoded, signed with
// upper(md5("<OutSum>:<InvId>:<token>")) in SignatureValue. The payment postback names its
// bill in TrsId; the payout, refund and chargeback postbacks are not the panel's business
// and are ignored. The panel asks Status anyway, and that is what decides.
func (p *cardlink) Webhook(_ context.Context, r adapter.WebhookRequest) (string, error) {
	form, err := url.ParseQuery(string(r.Body))
	if err != nil {
		return "", adapter.BadRequest("the postback is not form-encoded")
	}
	sum, inv, id := form.Get("OutSum"), form.Get("InvId"), form.Get("TrsId")
	if sum == "" || inv == "" || id == "" {
		return "", nil // not a payment postback
	}
	if !validSignature(r.Settings.String("api_token"), sum, inv, form.Get("SignatureValue")) {
		return "", adapter.BadRequest("the signature does not match the API token")
	}
	if !billRe.MatchString(id) {
		return "", adapter.BadRequest("the postback names no bill")
	}
	return id, nil
}

// validSignature checks a payment postback. The hash is md5 because that is what Cardlink
// signs with; the panel never takes a postback for payment on its own.
func validSignature(token, sum, inv, signature string) bool {
	if token == "" || signature == "" {
		return false
	}
	want := md5.Sum([]byte(sum + ":" + inv + ":" + token))
	got, err := hex.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want[:]) == 1
}
