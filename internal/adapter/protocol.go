// Package adapter is the shared part of every payment adapter: protocol v1 types, the
// HTTP server with its Bearer check, request limits and errors (see PROTOCOL.md). An
// adapter implements Provider; the server does the rest.
package adapter

import (
	"context"
	"net/http"
)

// Protocol is the protocol version this package speaks.
const Protocol = 1

// Text is a string per language: "ru" and "en".
type Text map[string]string

// Setting is one field of the provider settings form the panel builds.
type Setting struct {
	Key      string `json:"key"`
	Label    Text   `json:"label"`
	Type     string `json:"type"` // "string" | "bool"
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
	Pattern  string `json:"pattern,omitempty"`
}

// Info is the answer to GET /v1/info.
type Info struct {
	ID           string    `json:"id"`
	Protocol     int       `json:"protocol"`
	Version      string    `json:"version"`
	Name         Text      `json:"name"`
	Currencies   []string  `json:"currencies"`
	Capabilities []string  `json:"capabilities"`
	Settings     []Setting `json:"settings"`
	Help         Text      `json:"help"`
}

// Capabilities.
const (
	CapWebhook = "webhook"
	CapRefund  = "refund"
)

// Settings are the provider settings the panel sends with every request: a string or a
// bool per key. The server checks them against Info.Settings before the provider sees
// them. They must not be stored or logged.
type Settings map[string]any

// String is a string setting, "" when it is missing.
func (s Settings) String(key string) string {
	v, _ := s[key].(string)
	return v
}

// Bool is a bool setting, false when it is missing.
func (s Settings) Bool(key string) bool {
	v, _ := s[key].(bool)
	return v
}

// InvoiceRequest is the body of POST /v1/invoices.
type InvoiceRequest struct {
	Settings       Settings `json:"settings"`
	PaymentID      int64    `json:"payment_id"`
	IdempotencyKey string   `json:"idempotency_key"`
	Amount         int64    `json:"amount"` // minor units
	Currency       string   `json:"currency"`
	Description    string   `json:"description"`
	ReturnURL      string   `json:"return_url"`
	WebhookURL     string   `json:"webhook_url"`
}

// Invoice is the answer to POST /v1/invoices.
type Invoice struct {
	ExternalID string `json:"external_id"`
	PayURL     string `json:"pay_url"`
}

// Invoice statuses.
const (
	StatusPending  = "pending"
	StatusPaid     = "paid"
	StatusCanceled = "canceled"
)

// Status is the answer to POST /v1/status: what the provider says, amount in minor units.
type Status struct {
	Status   string `json:"status"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// WebhookRequest is the provider's notification as the panel received it.
type WebhookRequest struct {
	Settings Settings    `json:"settings"`
	RemoteIP string      `json:"remote_ip"`
	Headers  http.Header `json:"headers"` // canonical keys: use Headers.Get
	Body     []byte      `json:"body"`    // base64 in JSON
}

// Provider is one payment provider. Methods return *Error for answers the panel should
// see as they are; any other error means the provider could not be reached
// (provider_unavailable).
type Provider interface {
	Info() Info
	Check(ctx context.Context, s Settings) error
	CreateInvoice(ctx context.Context, r InvoiceRequest) (Invoice, error)
	Status(ctx context.Context, s Settings, externalID string) (Status, error)
	// Webhook returns the external id the notification is about, "" to ignore it, or
	// an error (BadRequest for a forged one).
	Webhook(ctx context.Context, r WebhookRequest) (externalID string, err error)
}

// Refunder is a Provider with the "refund" capability.
type Refunder interface {
	Refund(ctx context.Context, s Settings, externalID string, amount int64) error
}
