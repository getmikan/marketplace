# mikan marketplace

Payment adapters for the [mikan](https://github.com/Miroshka000/mikan) VPN panel, and the
signed catalog the panel installs them from.

An adapter is a small stateless HTTP service that connects the panel to one payment
provider. The panel lists the catalog under Payments → «Добавить способ оплаты»; the host
pulls the adapter's image by digest and runs it next to the panel, on loopback. The
contract between them is [PROTOCOL.md](PROTOCOL.md).

## Adapters

| id | Provider | Currencies | Capabilities |
|---|---|---|---|
| [`yookassa`](adapters/yookassa) | ЮKassa: bank cards and SBP | RUB | webhook, refund |
| [`cryptobot`](adapters/cryptobot) | @CryptoBot (Crypto Pay): cryptocurrency, priced in fiat | RUB, USD, EUR | webhook |
| [`platega`](adapters/platega) | Platega: SBP, cards, Sberpay, crypto | RUB | webhook |
| [`rollypay`](adapters/rollypay) | RollyPay: SBP, cards, crypto | RUB | webhook |

Each needs panel 0.4.3 or later.

## Layout

```
adapters/<id>/       one adapter: main.go, the provider client, tests, adapter.json, Dockerfile
internal/adapter/    the shared server: env, loopback check, Bearer auth, limits, errors, settings validation
internal/catalog/    adapter.json and index.json: types, checks, signing
cmd/index/           builds and signs dist/index.json; verifies it
PROTOCOL.md          the protocol, for adapter authors
```

Go 1.27, standard library only.

```sh
gofmt -l . && go vet ./... && go test ./...
docker buildx build --platform linux/amd64 -f adapters/yookassa/Dockerfile -t adapter-yookassa:dev --load .
docker run --rm --network host -e MIKAN_ADAPTER_LISTEN=127.0.0.1:41873 -e MIKAN_ADAPTER_TOKEN=test adapter-yookassa:dev
curl -H 'Authorization: Bearer test' http://127.0.0.1:41873/v1/info
```

## Writing an adapter

1. Read [PROTOCOL.md](PROTOCOL.md), especially the security section.
2. Create `adapters/<id>/` (lowercase letters, digits, dashes):
   - `adapter.json`, the catalog entry without the digest:
     ```json
     {
       "id": "examplepay",
       "name": {"ru": "Example Pay", "en": "Example Pay"},
       "description": {"ru": "Карты", "en": "Cards"},
       "version": "1.0.0",
       "protocol": 1,
       "image": "ghcr.io/getmikan/adapter-examplepay",
       "min_panel": "0.4.3",
       "homepage": "https://github.com/getmikan/marketplace/tree/main/adapters/examplepay"
     }
     ```
     `version` belongs to this adapter. Increase it when its code, Dockerfile,
     embedded manifest, or shared server code changes.
   - `main.go` embeds `adapter.json` and calls `adapter.Run` with your provider, which
     implements `adapter.Provider` (and `adapter.Refunder` with the `refund` capability).
     The server validates the settings against your `Info().Settings`, checks invoice
     requests, maps errors and logs requests; your code only talks to the provider. Return
     `*adapter.Error` (`adapter.BadCredentials`, `adapter.NotFound`, `adapter.Refused`, …)
     for answers the admin should see; any other error becomes `provider_unavailable`
     without its text. Use `adapter.HTTPClient()` (15 s timeout) for provider calls.
   - Tests with an `httptest` fake of the provider, through `adapter.NewHandler`: info,
     check with good and bad credentials, the idempotency key and the amount of a new
     invoice, the status mapping with amount and currency, a valid, a forged and an
     ignored webhook, and that the secrets never reach the log. The two adapters here show
     how.
   - `Dockerfile`: copy one of the existing ones and change the id.
   - `README.md`: the settings, where to find them, the webhook setup.
3. Open a pull request. CI runs gofmt, vet, the tests and builds the image for amd64 and
   arm64; `go run ./cmd/index list` checks every `adapter.json`.

## Releases and signing

Each adapter has its own version. To release a changed adapter, increase only its
`adapter.json` version and merge the change to `main`. [release.yml](.github/workflows/release.yml)
then:

1. Runs tests and verifies the previous release's `index.json.sig` with the trusted
   release public key. It compares the previous release tag with the new commit.
2. Requires a newer adapter version for changes to its image inputs. Documentation and
   tests alone need no bump. A change to shared server code or Go dependencies requires
   a version increase for every adapter.
3. Builds and pushes only changed images for amd64 and arm64, each tagged with its own
   adapter version. Unchanged image digests come from the verified previous catalog.
4. Signs a new complete catalog and publishes it under an automatic `catalog-<run>-<attempt>`
   tag. The panel reads `releases/latest/download/index.json`.

Unrelated documentation and workflow changes do not publish a new catalog. An unavailable
previous release, invalid signature, unknown image input, or missing digest fails the
release. Adapter removal needs a separate explicit process.

`index.json.sig` is `base64(ed25519.Sign(key, <exact bytes of index.json>))`, the same
format as the panel's release manifest, and the panel and the host check it with the same
public key, `Z3wSIPBSaJxh5CsGO8eINI0aM0kyrQ46EcJSNeH85W8=`.

Before the first release the maintainer must:

- add the repository secret **`MARKETPLACE_SIGNING_KEY`**: the PEM (PKCS#8) Ed25519
  private key, **the same key as the panel's `RELEASE_SIGNING_KEY`**. The workflow refuses
  to publish a catalog that this public key does not verify;
- after the first push of each image, make the package `adapter-<id>` **public** in the
  organization's packages settings (GitHub creates new packages private, and the host pulls
  without credentials), and check that it is linked to this repository.

Check a published catalog by hand:

```sh
curl -fsSLO https://github.com/getmikan/marketplace/releases/latest/download/index.json
curl -fsSLO https://github.com/getmikan/marketplace/releases/latest/download/index.json.sig
go run ./cmd/index verify index.json
```

## License

[GPL-3.0-only](LICENSE), as the panel.
