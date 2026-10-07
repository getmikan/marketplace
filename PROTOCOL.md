# mikan payment adapter protocol, version 1

A payment adapter connects the [mikan](https://github.com/Miroshka000/mikan) panel to one
payment provider. It is a small stateless HTTP service in a container on the same host as
the panel. It knows the provider's API and nothing about users or tariffs.

- **The panel** keeps the provider settings (secrets included) in its database, creates
  and tracks payments, and decides when a payment is paid. It never trusts a webhook by
  itself: it asks the adapter for the invoice status and compares the amount and the
  currency with the payment it created.
- **The adapter** gets the settings with every request and must not store or log them.
- **The host** (the `mikan` installer/CLI) installs, updates and removes adapter
  containers from the signed catalog.

## Transport

| | |
|---|---|
| Address | `MIKAN_ADAPTER_LISTEN`, an IP literal on loopback and a fixed port, e.g. `127.0.0.1:41873`. The adapter refuses to start with anything else: `0.0.0.0`, a public address, a host name such as `localhost`, or port `0`. The container runs on the host network. |
| Auth | Every request carries `Authorization: Bearer <MIKAN_ADAPTER_TOKEN>` (a random token the host generates per install and gives to both sides). Compare it in constant time. Anything else gets `401` with code `unauthorized`, before the path is even looked at. |
| Bodies | JSON, UTF-8, at most 1 MiB. Unknown request fields must be ignored, so the panel can add fields later. |
| Amounts | Integers in minor units: kopecks for RUB, cents for USD and EUR. |
| Timeouts | The panel waits 15 s per call. Keep provider calls well inside that. |

### Errors

Any non-2xx answer has this body; the message is human readable and contains no secrets:

```json
{"code": "bad_credentials", "message": "YooKassa refused the shop ID or the secret key"}
```

| Code | HTTP | When |
|---|---|---|
| `bad_settings` | 422 | The settings fail validation (missing, wrong type, does not match `pattern`). |
| `bad_credentials` | 422 | The provider refused the credentials. |
| `provider_unavailable` | 502 | The provider could not be reached, timed out or answered nonsense. |
| `not_found` | 404 | No such invoice at the provider; an unknown endpoint; `/v1/refund` without the `refund` capability. |
| `bad_request` | 400 | A malformed request; a forged webhook. |
| `unauthorized` | 401 | A missing or wrong Bearer token. |
| `method_not_allowed` | 405 | `/v1/info` is `GET`, every other endpoint is `POST`. |

Any other code is the provider's own refusal and is shown as it is, e.g.
`yookassa_invalid_request` (422). Use `<adapter id>_<provider's code>`, snake_case.

## Endpoints

### `GET /v1/info`

```json
{
  "id": "yookassa",
  "protocol": 1,
  "version": "1.0.0",
  "name": {"ru": "ЮKassa", "en": "YooKassa"},
  "currencies": ["RUB"],
  "capabilities": ["webhook", "refund"],
  "settings": [
    {"key": "shop_id", "label": {"ru": "shopId", "en": "Shop ID"}, "type": "string", "secret": false, "required": true, "pattern": "^[0-9]{1,20}$"},
    {"key": "secret_key", "label": {"ru": "Секретный ключ", "en": "Secret key"}, "type": "string", "secret": true, "required": true, "pattern": "^[!-~]{1,200}$"}
  ],
  "help": {"ru": "Ключи — в личном кабинете ЮKassa → Интеграция → Ключи API.", "en": "The keys are in the YooKassa dashboard → Integration → API keys."}
}
```

- `id`, `version` and `name` are the same as in the catalog entry.
- `type` is `string` or `bool`. The panel builds the settings form from `settings`, keeps
  `secret` values write-only (never sent back to the browser) and validates `required` and
  `pattern` (an RE2 regular expression) before calling the adapter. The adapter validates
  them again and answers `bad_settings`.
- `capabilities`: `webhook` (the provider notifies about payments) and `refund` (the
  adapter serves `/v1/refund`).
- `help` tells the admin where to find the keys and where to enter the panel's
  notification URL in the provider's dashboard.

### `POST /v1/check`

```json
{"settings": {"shop_id": "123456", "secret_key": "live_…"}}
```

`200 {}` when the provider accepts the credentials, else an error (`bad_credentials`). The
panel calls it before saving changed settings.

### `POST /v1/invoices`

```json
{
  "settings": {"shop_id": "123456", "secret_key": "live_…"},
  "payment_id": 4217,
  "idempotency_key": "mikan-4217",
  "amount": 19900,
  "currency": "RUB",
  "description": "VPN · Месяц",
  "return_url": "https://panel.example.com:2053/s9Hj.../tg",
  "webhook_url": "https://panel.example.com:2053/s9Hj.../pay/addon/yookassa/<token>"
}
```

→ `200 {"external_id": "2f1c…", "pay_url": "https://yoomoney.ru/checkout/…"}`

- `payment_id` is positive; `amount` is positive; `currency` is one of `currencies`;
  `return_url` and `webhook_url` are empty or absolute `http(s)` URLs. Otherwise
  `bad_request`.
- `idempotency_key` is 1–64 printable ASCII characters without spaces. **The same key must
  not create a second invoice at the provider**: pass it as the provider's idempotency key,
  or, if the provider has none, look for the invoice the key already created (the
  CryptoBot adapter stores the key in the invoice payload and looks it up first).
- `webhook_url` is where the panel receives the provider's notifications. Providers that
  take a notification URL per invoice should send it; for the others (YooKassa, CryptoBot, Platega, RollyPay)
  the admin enters it in the provider's dashboard.
- An adapter may require `return_url` if its provider does (`bad_request` without it).

### `POST /v1/status`

```json
{"settings": {…}, "external_id": "2f1c…"}
```

→ `200 {"status": "pending" | "paid" | "canceled", "amount": 19900, "currency": "RUB"}`

- `paid` only when the money is final (YooKassa `succeeded`, CryptoBot `paid`).
- `canceled` when it can no longer be paid (YooKassa `canceled`, CryptoBot `expired`).
- Anything else is `pending`.
- `amount` and `currency` are the provider's, not an echo of the request: the panel compares
  them with the payment it created and refuses a mismatch.
- `not_found` when the provider has no such invoice.

### `POST /v1/webhook`

The panel receives the provider's request at its own URL and forwards it as it came:

```json
{"settings": {…}, "remote_ip": "185.71.76.10", "headers": {"Content-Type": ["application/json"]}, "body": "<base64 of the raw body>"}
```

→ `200 {"external_id": "2f1c…"}` when it is about one of the provider's invoices,
`200 {}` to ignore it (an event the panel does not need), or an error: `bad_request` for a
forged request (a bad signature, a foreign source address). Header names are
case-insensitive; `remote_ip` is the address the provider connected from, as the panel
determined it.

The adapter checks whatever the provider offers (a signature over the raw body, the source
address). The panel then calls `/v1/status` anyway and answers the provider only after
that, so a webhook can never mark a payment paid by itself.

### `POST /v1/refund` (only with the `refund` capability)

```json
{"settings": {…}, "external_id": "2f1c…", "amount": 19900}
```

→ `200 {}` when the provider accepted the refund (it may still be processing). The request
carries no idempotency key: **a retried refund must not refund twice**. Derive the
provider's idempotency key from `external_id` and `amount` (the YooKassa adapter uses
`mikan-refund-` + the first 16 bytes of `sha256("<external_id>:<amount>")` in hex). The
refund is in the payment's own currency.

Without the `refund` capability the endpoint answers `not_found`.

## Security

- **Settings come with every request.** Use them for that request only. Do not write them
  to disk, keep them in memory between requests, put them in URLs, or log them. Log only
  codes, statuses and external ids.
- **Error messages reach the admin's browser.** Do not echo settings or raw transport
  errors (they carry URLs and addresses) into `message`.
- **Loopback only.** Refuse to listen anywhere but a loopback IP; the Bearer token is the
  second line, not the only one.
- **Webhooks are hints.** Verify what the provider offers and answer `bad_request` for a
  forgery, but remember the panel re-checks every webhook with `/v1/status`. Never derive
  `paid` from a webhook body.
- **Validate at the boundary.** Ids from the request go into provider URLs: check their
  format first (the YooKassa adapter refuses anything but `[0-9A-Za-z-]`).
- **Containers** run non-root (65532), with a read-only root file system, no capabilities
  and the host network. The adapter must not need to write files.

## Catalog

The panel offers the adapters listed in `index.json`, published with every catalog release
of [getmikan/marketplace](https://github.com/getmikan/marketplace):

- `https://github.com/getmikan/marketplace/releases/latest/download/index.json`
- `https://github.com/getmikan/marketplace/releases/latest/download/index.json.sig`

```json
{
  "version": 1,
  "updated": "2026-10-02T00:00:00Z",
  "adapters": [
    {
      "id": "yookassa",
      "category": "payments",
      "name": {"ru": "ЮKassa", "en": "YooKassa"},
      "description": {"ru": "Банковские карты и СБП", "en": "Bank cards and SBP"},
      "version": "1.0.0",
      "protocol": 1,
      "image": "ghcr.io/getmikan/adapter-yookassa",
      "digest": "sha256:…",
      "min_panel": "0.4.3",
      "homepage": "https://github.com/getmikan/marketplace/tree/main/payments/yookassa"
    }
  ]
}
```

- `version` is the format version (1). `updated` is RFC 3339 UTC.
- `id`: lowercase letters, digits and dashes. `image` is `ghcr.io/getmikan/adapter-<id>`;
  images are pulled **by digest only** (`image@digest`), the multi-arch (amd64, arm64)
  index digest.
- `category`: the package, `payments` or `tools`. The `adapters` list holds both, so a
  catalog from before the packages, without `category`, holds payment adapters. A payment
  adapter speaks this protocol (1); a tool never does, so a panel that knows no categories
  never offers a tool as a payment method. A tool's image is `ghcr.io/getmikan/tool-<id>`.
- `min_panel`: the oldest panel version that may install it.
- An adapter whose `protocol` the panel does not know is not offered.

`index.json.sig` is `base64(ed25519.Sign(key, <the exact bytes of index.json>))`, signed
with the mikan release key, the same key as the panel's release manifest. The panel and the
host verify it with the public key built into them,
`Z3wSIPBSaJxh5CsGO8eINI0aM0kyrQ46EcJSNeH85W8=` (raw Ed25519, base64), before they parse
the file.

## A minimal adapter

The adapters in this repository share `internal/adapter`, which does all of the above;
see [README.md](README.md). An adapter in another language only has to speak HTTP. The
server part, in plain Go:

```go
// A minimal protocol v1 adapter for an imaginary provider "Example Pay": the server
// part is complete, the provider calls are left to you.
package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	listen, token := os.Getenv("MIKAN_ADAPTER_LISTEN"), os.Getenv("MIKAN_ADAPTER_TOKEN")
	host, port, err := net.SplitHostPort(listen)
	if ip, perr := netip.ParseAddr(host); err != nil || perr != nil || !ip.IsLoopback() || port == "0" || token == "" {
		log.Fatal("MIKAN_ADAPTER_LISTEN must be a loopback ip:port and MIKAN_ADAPTER_TOKEN set")
	}
	want := sha256.Sum256([]byte(token))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(auth))
		if !ok || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			reply(w, 401, apiError{Code: "unauthorized", Message: "a valid Bearer token is required"})
			return
		}
		if r.URL.Path == "/v1/info" {
			reply(w, 200, map[string]any{
				"id": "examplepay", "protocol": 1, "version": "1.0.0",
				"name": map[string]string{"ru": "Example Pay", "en": "Example Pay"}, "currencies": []string{"RUB"},
				"capabilities": []string{"webhook"},
				"settings": []map[string]any{{"key": "api_key", "label": map[string]string{"ru": "Ключ API", "en": "API key"},
					"type": "string", "secret": true, "required": true}},
				"help": map[string]string{"ru": "Ключ — в кабинете Example Pay.", "en": "The key is in the Example Pay dashboard."},
			})
			return
		}
		var req struct {
			Settings       map[string]any `json:"settings"`
			IdempotencyKey string         `json:"idempotency_key"`
			Amount         int64          `json:"amount"`
			Currency       string         `json:"currency"`
			ExternalID     string         `json:"external_id"`
			RemoteIP       string         `json:"remote_ip"`
			Headers        http.Header    `json:"headers"`
			Body           []byte         `json:"body"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			reply(w, 400, apiError{Code: "bad_request", Message: "invalid JSON"})
			return
		}
		key, _ := req.Settings["api_key"].(string) // use it for this request only: never store or log it
		if key == "" {
			reply(w, 422, apiError{Code: "bad_settings", Message: "api_key is required"})
			return
		}
		switch r.URL.Path {
		case "/v1/check": // ask the provider whether the key works → {} or bad_credentials
		case "/v1/invoices": // create an invoice with req.IdempotencyKey → {"external_id", "pay_url"}
		case "/v1/status": // fetch req.ExternalID → {"status", "amount", "currency"}
		case "/v1/webhook": // verify req.Body (signature, req.RemoteIP) → {"external_id"} or {}
		default:
			reply(w, 404, apiError{Code: "not_found", Message: "no such endpoint"})
			return
		}
		reply(w, 502, apiError{Code: "provider_unavailable", Message: "not implemented yet"})
	})
	log.Fatal(http.ListenAndServe(listen, nil))
}
```

Try it:

```sh
MIKAN_ADAPTER_LISTEN=127.0.0.1:41873 MIKAN_ADAPTER_TOKEN=test go run . &
curl -H 'Authorization: Bearer test' http://127.0.0.1:41873/v1/info
```
