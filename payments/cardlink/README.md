# Cardlink adapter

Bank cards and SBP through [Cardlink](https://cardlink.link). Protocol:
[PROTOCOL.md](../../PROTOCOL.md). Image: `ghcr.io/getmikan/adapter-cardlink`. Currencies:
RUB, USD, EUR. API base: `https://cardlink.link/api/v1`, reference:
<https://cardlink.link/reference/api>.

## Settings

| key | | where |
|---|---|---|
| `api_token` | secret | Cardlink dashboard → Integrations → API; it is also the key the postback signature is made with |
| `shop_id` | required | the shop's page in the dashboard; without the right one the payment form loses the panel's return and notification URLs |
| `payment_method` | optional | `BANK_CARD` or `SBP`; empty: the payer picks on Cardlink's page |
| `payer_pays_commission` | bool | on: Cardlink's fee is added to what the payer pays, so the panel still gets the price of the tariff |

Set the notification URL the panel shows for this adapter as the shop's **Result URL**:
Cardlink takes no notification URL per bill. Give the shop the panel's own domain as well,
the one the subscription links use — Cardlink matches it against `success_url` and
`fail_url` and drops them otherwise, and the payer is then left on its page.

## Behaviour

| | |
|---|---|
| check | `GET /balance` with the token (the reference also gives it as `/merchant/balance`, which is tried when the first is not there); 401/403 → `bad_credentials`. The shop id cannot be checked this cheaply |
| invoice | `GET /bill/search?order_id=` first: Cardlink has no idempotency key of its own and keeps no order ids unique, so the bill an earlier call made is returned instead of a second one; one that is there but comes without a link gives `cardlink_bill_exists`, and a dead one (`FAIL`, or no longer active) is passed over. Then `POST /bill/create` with `order_id` = the idempotency key, the amount as `"199.00"`, `currency_in`, `type=normal`, `ttl=86400` (a day, as the panel's own invoice), and `success_url`, `fail_url`, `return_url` = `return_url`. The external id is `bill_id`, the payment page `link_page_url` |
| status | `GET /bill/status?id=`: `SUCCESS` and `OVERPAID` → paid; `FAIL`, and a bill that is no longer `active`, → canceled; the rest → pending. `UNDERPAID` is **pending**: money came, but less than the bill, and Cardlink gives the bill's own amount, so calling it paid would say more arrived than did — settle those in the Cardlink dashboard. Extra zero decimal places in the amount are accepted, fractional kopecks are not |
| webhook | the postback is form-encoded; `SignatureValue` must be the uppercase MD5 of `OutSum + ":" + InvId + ":" + api_token`, else `bad_request`. The payment postback names its bill in `TrsId`; the payout, refund and chargeback postbacks are ignored. MD5 is what Cardlink signs with; the panel asks `/v1/status` about every postback anyway, so a postback cannot pay a payment by itself |
| refund | not supported (no `refund` capability): Cardlink opens its refund API on a support request, so refund in its dashboard. A payment the panel cannot refund stays as it is, with the reason on it |

Errors: 401/403 → `bad_credentials`, 404 → `not_found`, 429 and 5xx →
`provider_unavailable`, other refusals → `cardlink_http_<status>`.

Not checked against the live API: the shape of the `bill/search` answer is read loosely (a
bare array, an object holding one, or a paginator holding that), the two spellings of the
balance path come from the reference itself, and the postback is trusted to be the payment
one only when it carries `OutSum`, `InvId` and `TrsId` together.
