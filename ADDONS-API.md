# The addon API (draft for discussion)

Status: **a proposal**, nothing here is built yet. It decides how tools (`tools/`) talk to
the panel, so that the Telegram bot and its Mini App can leave the panel, and admins can
write addons of their own. Payment adapters keep [PROTOCOL.md](PROTOCOL.md) as it is.

## Two kinds of addons

| | Panel addons (tools) | Node addons |
|---|---|---|
| Runs | a container next to the panel, like a payment adapter | inside every node, in the traffic path |
| Examples | the Telegram bot and Mini App, alert senders, CRM hooks | the torrent blocker, ingress and egress filters |
| Comes from | the marketplace (`tools/`), signed catalog | built into the node; switched on in Addons |
| Talks over | this API | the node state the panel already pushes |

Node addons stay built in: they see every user's traffic, the node runs without
privileges, and a third-party binary has no place there. What the marketplace may ship for
them later is **data**: signed lists (ports, networks, domains) a filter uses.

## Panel addons: the protocol (version 2)

A tool is an HTTP service on loopback, like a payment adapter, with the same hardening
(no capabilities, read-only root, 128 MB, loopback only). It speaks protocol 2, so
panels that know only payments never offer it. Talk goes both ways:

```
panel ──(adapter token)──▶ tool      /v2/info, /v2/configure, /v2/events, /v2/actions, /v2/http
tool  ──(addon key)──────▶ panel     /api/v1/… on a loopback listener, limited to its scopes
```

### Panel → tool

| Endpoint | What for |
|---|---|
| `GET /v2/info` | id, version, protocol 2, the settings schema (the payment one, extended), the scopes it wants, the events it takes, its actions, the public paths it serves |
| `POST /v2/configure` | the admin's settings, the panel's address and the tool's addon key. Sent after start and on every change; the tool keeps them in memory only, so a restart costs nothing |
| `POST /v2/events` | a batch of events (below) |
| `POST /v2/actions/{name}` | a button in the tool's page, with a form (e.g. "Broadcast" with a text) |
| `* /v2/http/{path}` | public requests the panel forwards: Telegram webhooks, the Mini App, provider callbacks |

The adapter token stays as today: the host generates it, the panel calls the tool with it.

### Tool → panel: the addon key

- On install the panel makes the tool an **addon key**: a new kind in `api_keys` (next to
  `read` and `full`), bound to the addon id and to the **scopes** it asked for and the
  admin granted. The admin sees the list before installing ("reads users", "creates
  invoices", "sends to Telegram users"…). It is handed over in `/v2/configure`, never
  written to disk on the tool's side, and dropped with the addon.
- The API is the panel's own `/api/v1`, on a **loopback-only listener** for addons
  (plain HTTP on 127.0.0.1, no admin path, not reachable from outside). The panel's
  public port does not take addon keys.
- Each operation names its scope. An operation without one (settings, admins, keys,
  backups, nodes' secrets) is refused to every addon key. `sessionOnly` stays as it is.
- Rate limits per key; every write is in the audit log with the addon's name.

First scopes, from what the bot needs:

| Scope | Gives |
|---|---|
| `users:read` | users, their state, traffic, devices, pools, subscription links |
| `users:write` | create a user, extend, change the tariff, unbind a device |
| `shop:read` | offers, packages, payment methods, the trial's availability, as a buyer sees them |
| `shop:write` | create an invoice, take a trial, check and redeem a promo code |
| `telegram` | the Telegram links and chats: link, unlink, the current subscription, blocked chats, broadcast targets, notice records |
| `payments:provide` | be a payment method (Stars): the panel asks the tool for invoice links and refunds, the tool reports payments |
| `alerts:read` | infrastructure alerts as events |
| `backups:read` | the encrypted backup when it is made |

New operations are needed for most of these (today the bot calls the database directly);
the list is in "Moving the bot".

### Events

- The panel writes events to an **outbox table** in the same transaction as the change,
  then delivers them in order, in batches, with retries and backoff. Delivery is at least
  once; each event has an id, and the tool skips ids it has seen.
- A tool gets only the events it listed in `/v2/info` and has the scope for.
- After 3 days undelivered (the tool is down, removed), events are dropped and the page of
  the addon says so.

First events: `user.created`, `user.updated`, `user.expiring` (days left, the panel's
notice periods), `user.traffic_low`, `user.expired`, `payment.paid`, `payment.refunded`,
`alert.node` (down, up, blocked port), `backup.ready` (a one-time download link).

### Settings, pages and public paths

- **Settings**: the schema from `/v2/info`, drawn by the panel under Addons → the tool, as
  payment methods are now. Secret fields are kept by the panel and never shown again.
- **Actions**: buttons with a small form; the answer is shown as a notice.
- **Custom pages** (later): the tool serves a page the panel shows in a sandboxed frame
  under Addons → the tool, with a postMessage bridge to the panel's API under the tool's
  own key. Enough for the bot's menu editor; nothing else in the panel needs it.
- **Public paths**: `/<sub path>/x/<addon id>/…` goes to `/v2/http/…` of the tool, with the
  client's address in a header. The Mini App and Telegram's webhook live there.

### Outbound network

A tool's container reaches the internet directly. The bot today can reach Telegram
through a node (`telegram.route`); for that the panel offers tools a local proxy through a
chosen node (scope `net:proxy`), so the setting keeps working.

### Your own addons

- The catalog stays signed: what it lists, the maintainers have reviewed.
- An admin can still run an addon of their own: `mikan addon install --image ghcr.io/me/x@sha256:…`
  installs an unsigned image after a plain warning, and the panel marks it **unverified**
  everywhere. The same scopes and consent apply.
- `tools/example/`: a minimal tool in Go with tests, the starting point for authors, and
  a Go package (`internal/tool`) like `internal/adapter` for payments.

## Moving the bot

The bot's data stays in the panel (`tg_chats`, `tg_links`, `tg_notices`, `trials`,
`payments.tg_id`): billing, promo codes and the trial use it too. The bot becomes a
stateless tool on top of the API.

| Today, inside the panel | With the API |
|---|---|
| reads users, tariffs, pools via the database | `users:read`, `shop:read` |
| links Telegram accounts, keeps chats and menus | `telegram` (new operations) |
| shop, invoices, packages, trial, promo | `shop:write` (new operations, what `/<sub>/tg/shop`, `/tg/pay`, `/tg/promo` do now) |
| Stars: invoice links, pre-checkout, refunds; billing calls `Paid`/`Refunded` | `payments:provide` and the `payment.*` events |
| expiry and traffic notices every 10 minutes | `user.expiring`, `user.traffic_low` |
| broadcast | an action; targets from `telegram` |
| infrastructure alerts and Telegram backups use the bot's client | `alert.node`, `backup.ready`; the bot sends them |
| the Mini App: `/<sub>/tg`, initData checked with the bot token | served by the tool under its public path; the shop calls go through the API |
| `telegram.route` through a node | `net:proxy` |

**For those who run the bot today:**

1. A panel release with the API keeps the built-in bot. Nothing changes.
2. The bot appears in the marketplace. Installing it copies the token, the menus and
   texts, the route and the alert chat into the tool's settings, stops the built-in bot,
   and the tool takes over the same long poll: users notice nothing.
3. A later release turns the built-in bot off for good and offers the install on the
   Telegram page. Removing the tool brings nothing back by itself: the data is the
   panel's, a reinstall continues where it stopped.

## Node addons: ingress and egress filters

Built in, next to the torrent blocker, switched on in Addons, delivered in the node state
the panel already pushes.

**Egress** (where users may go):

- presets: **mail** (25, 465, 587, 2525; 25 is closed already), **private networks**
  (closed already, now visible and explained), **your list**: ports, networks, domains;
- global rules go in the node's routing rules as REJECT, before the cascade and WARP;
- exceptions per user and per tariff, the way the torrent blocker has them, are checked in
  the node's connection handler, since the routing rules are not per user;
- blocked attempts counted per user, like the blocker's catches, without the ban.

**Ingress** (who may connect):

- deny or allow lists of networks, checked on every new connection before the user is
  admitted (the node has the client's address there);
- countries: the panel turns them into networks from a GeoIP list and pushes those; the
  node gets no database;
- the node's API port is not affected: it is closed to all but the panel already.

A node older than the release ignores what it does not know, so the Addons page names the
nodes that need an update for the filters to apply.

## Order of work

1. **Filters** (panel and node): independent of the rest, useful now.
2. **Protocol 2 and the addon key**: info, configure, settings form, scopes and consent,
   the loopback listener, the outbox with the first events, `tools/example/`. The installer
   learns tools (category, image prefix `tool-`).
3. **The bot's API**: the new operations, public paths, `payments:provide`, `net:proxy`.
4. **The bot as a tool**, the move from the built-in one, then the Mini App.
5. **Custom pages** and unverified installs.

## Open questions

- Should a tool be able to add a **tab to the subscription page** (not only its own
  path), for example a support chat?
- Events for **every** user change, or only the listed ones? Many users and a busy panel
  make a lot of `user.updated`.
- Should node addons ever take third-party code (a WASM module with a fixed interface), or
  is data enough?
