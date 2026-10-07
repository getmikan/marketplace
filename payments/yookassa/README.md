# ЮKassa (YooKassa) adapter

Bank cards and SBP through [ЮKassa](https://yookassa.ru), API v3. Rubles only.
Protocol: [PROTOCOL.md](../../PROTOCOL.md). Image: `ghcr.io/getmikan/adapter-yookassa`.

## Settings

| key | | where |
|---|---|---|
| `shop_id` | digits | the YooKassa dashboard → Integration → API keys (shopId) |
| `secret_key` | secret | the same page; a `test_…` key of a test shop works the same way |

Test shops use the same API with their test keys, so there is no separate test switch.

In the dashboard → Integration → HTTP notifications, enter the notification URL the panel
shows for this adapter and turn on `payment.succeeded` and `payment.canceled`.

## Behaviour

| | |
|---|---|
| check | `GET /me` with the keys; 401 → `bad_credentials` |
| invoice | `POST /payments` with `Idempotence-Key: <idempotency_key>`, `capture: true`, a redirect confirmation to `return_url` (required), the description cut to 128 characters, metadata `mikan_payment_id` |
| status | `GET /payments/<id>`: `succeeded` → paid, `canceled` → canceled, anything else (`pending`, `waiting_for_capture`) → pending; the amount and currency are YooKassa's |
| webhook | YooKassa does not sign notifications: the source address must be one of [YooKassa's](https://yookassa.ru/developers/using-api/webhooks#ip), else `bad_request`. `payment.*` events name the payment; others (`refund.*`) are ignored |
| refund | `POST /refunds` in the payment's currency, with an idempotence key derived from the payment id and the amount, so a retry does not refund twice; a `canceled` refund → `yookassa_refund_canceled` |

Errors: 401 → `bad_credentials`, 404 → `not_found`, 429 and 5xx → `provider_unavailable`,
other refusals → `yookassa_<code>` with the field YooKassa names, e.g.
`yookassa_invalid_request` with `parameter receipt` when the shop requires 54-FZ receipts
(not supported yet).
