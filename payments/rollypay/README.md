# RollyPay adapter

SBP, cards and crypto through [RollyPay](https://docs.rollypay.io/). Protocol:
[PROTOCOL.md](../../PROTOCOL.md). Image: `ghcr.io/getmikan/adapter-rollypay`. Currency: RUB.
API base: `https://rollypay.io/api/v1`.

## Settings

| key | | where |
|---|---|---|
| `api_key` | secret | RollyPay dashboard → terminal settings (`X-API-Key`; one key, one terminal) |
| `signing_secret` | secret | the same place; signs webhooks only |
| `method` | optional | `sbp`, `card`, `intl_card`, `crypto`; empty: the payer picks on RollyPay's page |
| `test` | bool | sandbox: `test: true` on payments, no real money |

Set the notification URL the panel shows for this adapter as the terminal's `callback_url`.

## Behaviour

| | |
|---|---|
| check | `GET /terminals` with the key and expect a nonempty terminal list; 401 → `bad_credentials`. The live balance endpoint requires `terminal_id` even with a terminal API key. |
| invoice | `POST /payments` with `order_id` = the idempotency key (RollyPay: one order, one payment), the amount as `"199.00"`, `success_redirect_url` and `fail_redirect_url` = `return_url`. On 409 the live payment of that order is read from `GET /payments?order_id=` and returned; a closed one gives `rollypay_order_exists`. Every request carries a fresh `X-Nonce` |
| status | `GET /payments/<id>`: `paid` → paid; `expired`, `canceled`, `chargeback`, `refunded` → canceled; `created`, `processing` → pending. Amount and currency are the order's (`amount`, `payment_currency`), not the USDT figures. Extra zero decimal places in `amount` are accepted; fractional kopecks are rejected. |
| webhook | `X-Signature` must be the hex HMAC-SHA256 of `X-Timestamp + "." + body` keyed with `signing_secret`, else `bad_request`. `payment.paid` names the payment, other events are ignored. A late `paid` after `expired` is caught by the panel's status call |
| refund | not supported (no `refund` capability) |

Errors: 401/403 → `bad_credentials`, 404 → `not_found`, 429 and 5xx → `provider_unavailable`,
other refusals → `rollypay_http_<status>`.

Not checked against the live API: the shape of the payment list answer is read loosely
(a bare array or an object holding one), and the timestamp is not checked for age.
