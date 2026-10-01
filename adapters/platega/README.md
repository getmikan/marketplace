# Platega adapter

SBP, cards, Sberpay, international payments and crypto through [Platega](https://docs.platega.io/).
Protocol: [PROTOCOL.md](../../PROTOCOL.md). Image: `ghcr.io/getmikan/adapter-platega`. Currency: RUB.

## Settings

| key | | where |
|---|---|---|
| `merchant_id` | | Platega dashboard → Settings (`X-MerchantId`) |
| `secret` | secret | the same place (`X-Secret`) |
| `method` | optional | 2 SBP QR, 3 ERIP, 11 cards, 12 international, 13 crypto, 14 Sberpay; empty: the payer picks on Platega's page |

Under Callback URLs in the dashboard, enter the notification URL the panel shows for this adapter.

## Behaviour

| | |
|---|---|
| check | `GET /transaction/<zero uuid>`: 404 means the credentials are accepted, 401 → `bad_credentials` |
| invoice | `POST /v2/transaction/process` (or `/transaction/process` with `paymentMethod` when `method` is set); `orderId` and `payload` carry the idempotency key, `return` and `failedUrl` are `return_url`. Platega has no idempotency keys or lookup by order, so a retried request may open a second link; only the stored one is checked and an unpaid one expires |
| status | `GET /transaction/<id>`: `CONFIRMED` → paid, `CANCELED` and `CHARGEBACKED` → canceled, else pending; amount and currency are Platega's |
| webhook | Platega sends `X-MerchantId` and `X-Secret` with every callback; both must equal the settings (constant time), else `bad_request`. `CONFIRMED` names the transaction, other statuses are ignored |
| refund | not supported (no `refund` capability) |

Errors: 401/403 → `bad_credentials`, 404 → `not_found`, 429 and 5xx → `provider_unavailable`,
other refusals → `platega_http_<status>`.
