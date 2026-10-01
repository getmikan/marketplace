# CryptoBot adapter

Cryptocurrency through [@CryptoBot](https://t.me/CryptoBot)'s
[Crypto Pay API](https://help.crypt.bot/crypto-pay-api). Invoices are priced in fiat (RUB,
USD or EUR) and the payer picks the coin. Protocol: [PROTOCOL.md](../../PROTOCOL.md).
Image: `ghcr.io/getmikan/adapter-cryptobot`.

## Settings

| key | | where |
|---|---|---|
| `token` | secret | @CryptoBot → Crypto Pay → My Apps → the app → API Token |
| `testnet` | bool | on for an app made in [@CryptoTestnetBot](https://t.me/CryptoTestnetBot): calls go to `testnet-pay.crypt.bot` |

In the app's Webhooks, turn them on and enter the notification URL the panel shows for this
adapter.

## Behaviour

| | |
|---|---|
| check | `getMe` with the token; `UNAUTHORIZED` → `bad_credentials` |
| invoice | Crypto Pay has no idempotency keys, so the key goes into the invoice `payload`, and an active invoice with that payload among the 100 latest is returned instead of creating another. Then `createInvoice` with `currency_type: fiat`, the amount as `"199.00"`, `expires_in` one hour, the description cut to 1024 characters, and a «Return» button (`callback`) to `return_url`. The pay URL is `bot_invoice_url` |
| status | `getInvoices` by id: `paid` → paid, `expired` → canceled, `active` → pending; the amount (a string or a number in Crypto Pay's answers) and the fiat currency are CryptoBot's |
| webhook | `crypto-pay-api-signature` must be the HMAC-SHA256 of the raw body keyed with SHA-256 of the token, else `bad_request`. `invoice_paid` names the invoice; other updates are ignored |
| refund | not supported: Crypto Pay cannot refund an invoice (no `refund` capability) |

Errors: 401 → `bad_credentials`, 429 and 5xx → `provider_unavailable`, other refusals →
`cryptobot_<Crypto Pay's error name in lowercase>`.
