// Package catalog is the signed list of adapters the panel offers (index.json) and the
// adapter.json each adapter directory describes itself with. Adapters come in packages,
// one directory each: payments/ for the payment methods (protocol 1, PROTOCOL.md), tools/
// for the rest (protocol 2, PROTOCOL-v2.md).
//
// index.json is signed with the catalog's own key in the catalog's context: index.json.sig2
// holds base64(ed25519.Sign(key, Context + the file's exact bytes)), and the panel and the host
// trust it only with the key whose public half is PublicKey. index.json.sig, the release key's
// signature over the bytes alone (LegacyKey), is published too while panels before 0.5.1.1,
// which read only it, are out there.
package catalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// PublicKey is the public half of the catalog's key (raw Ed25519, base64): the same key as
// mikan's internal/release.CatalogKey, which the panel and the host verify the catalog with.
const PublicKey = "Z4QfL07dI/IRReSe6Gr76UcxxPoy4i2GiClBv8RcNuo="

// LegacyKey is the public half of the mikan release key, which signed the catalog for the
// panels before 0.5.1.1 (index.json.sig).
const LegacyKey = "Z3wSIPBSaJxh5CsGO8eINI0aM0kyrQ46EcJSNeH85W8="

// Context is what a catalog's signature covers before the file's bytes (mikan's
// internal/release.CatalogContext): a signature made for another kind of document never
// passes for the catalog.
const Context = "mikan catalog v1\n"

// SigSuffix names the signature in a context next to its file (index.json.sig2).
const SigSuffix = ".sig2"

// Format is the index.json format version ("version" in the file).
const Format = 1

// The packages: an adapter's category is the directory it sits in.
const (
	Payments = "payments"
	Tools    = "tools"
)

// Categories are the packages, in the order they are listed.
var Categories = []string{Payments, Tools}

// PaymentProtocol is the protocol of the payment adapters (PROTOCOL.md). Panels that know
// no categories offer every entry of this protocol as a payment method, so a tool never
// speaks it.
const PaymentProtocol = 1

// Protocol2 is the protocol of every other addon (PROTOCOL-v2.md): a bot, admin pages, or
// anything else that talks to the panel's API for addons. The tools speak it.
const Protocol2 = 2

// Kinds of a protocol 2 addon. A payment adapter has no kind in its entry: protocol 1 is it.
var Kinds = []string{"bot", "ui", "generic"}

// Modes of a protocol 2 addon: it serves /v2/* to the panel (http, the default when
// absent), or it only calls the panel (client).
var Modes = []string{"http", "client"}

// Permissions a protocol 2 addon may ask for; the admin approves them at install.
var Permissions = []string{"bot", "users:read", "users:write", "billing:invoice", "events", "kv", "ui"}

// MinMemMB and MaxMemMB bound the memory an addon may ask for; 0 is the host's default.
const (
	MinMemMB = 64
	MaxMemMB = 256
)

// ImagePrefix is where the payment adapters' images are published: ImagePrefix + id.
const ImagePrefix = "ghcr.io/getmikan/adapter-"

// ToolImagePrefix is where the tools' images are published: ToolImagePrefix + id.
const ToolImagePrefix = "ghcr.io/getmikan/tool-"

// ImageFor is the image an adapter of the category is published as.
func ImageFor(category, id string) string {
	if category == Tools {
		return ToolImagePrefix + id
	}
	return ImagePrefix + id
}

// Resources an addon asks the host for (protocol 2).
type Resources struct {
	MemMB int `json:"mem_mb,omitempty"`
}

// Manifest is an adapter's adapter.json: its catalog entry without the image digest.
// Kind, Mode, Permissions and Resources are protocol 2 only.
type Manifest struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Version     string            `json:"version"`
	Protocol    int               `json:"protocol"`
	Kind        string            `json:"kind,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	Resources   Resources         `json:"resources,omitzero"`
	Image       string            `json:"image"`
	MinPanel    string            `json:"min_panel"`
	Homepage    string            `json:"homepage"`
}

// Entry is one adapter in index.json. The protocol 2 fields are left out when empty, so a
// payment adapter's entry is the same as before them; their names are the panel's
// (Entry in internal/panel/addons of mikan).
type Entry struct {
	ID          string            `json:"id"`
	Category    string            `json:"category"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Version     string            `json:"version"`
	Protocol    int               `json:"protocol"`
	Kind        string            `json:"kind,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	Resources   Resources         `json:"resources,omitzero"`
	Image       string            `json:"image"`
	Digest      string            `json:"digest"`
	MinPanel    string            `json:"min_panel"`
	Homepage    string            `json:"homepage"`
}

// manifest is the entry without its digest.
func (e Entry) manifest() Manifest {
	return Manifest{ID: e.ID, Category: e.Category, Name: e.Name, Description: e.Description, Version: e.Version, Protocol: e.Protocol,
		Kind: e.Kind, Mode: e.Mode, Permissions: e.Permissions, Resources: e.Resources, Image: e.Image, MinPanel: e.MinPanel, Homepage: e.Homepage}
}

// entry is the manifest with the digest of its pushed image.
func (m Manifest) entry(digest string) Entry {
	return Entry{ID: m.ID, Category: m.Category, Name: m.Name, Description: m.Description, Version: m.Version, Protocol: m.Protocol,
		Kind: m.Kind, Mode: m.Mode, Permissions: m.Permissions, Resources: m.Resources, Image: m.Image, Digest: digest, MinPanel: m.MinPanel, Homepage: m.Homepage}
}

// Index is index.json.
type Index struct {
	Version  int       `json:"version"`
	Updated  time.Time `json:"updated"`
	Adapters []Entry   `json:"adapters"`
}

var (
	ErrSignature = errors.New("catalog: bad signature")
	idRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// versionRe is the panel's version grammar (internal/release of mikan): x.y.z with an
	// optional fourth number, as mikan's own releases have (0.5.1.0), and a prerelease.
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ParseManifest decodes and checks an adapter.json.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := decodeStrict(data, &m); err != nil {
		return m, fmt.Errorf("adapter.json: %w", err)
	}
	return m, m.Check()
}

// Check is what a catalog entry must satisfy, apart from the digest.
func (m Manifest) Check() error {
	switch {
	case !idRe.MatchString(m.ID):
		return fmt.Errorf("adapter %q: id must be lowercase letters, digits and dashes", m.ID)
	case !slices.Contains(Categories, m.Category):
		return fmt.Errorf("adapter %s: category %q is not %s", m.ID, m.Category, strings.Join(Categories, " or "))
	case m.Name["ru"] == "" || m.Name["en"] == "" || m.Description["ru"] == "" || m.Description["en"] == "":
		return fmt.Errorf("adapter %s: name and description need ru and en", m.ID)
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("adapter %s: version %q is not x.y.z[.w][-pre]", m.ID, m.Version)
	case m.Protocol != PaymentProtocol && m.Protocol != Protocol2:
		return fmt.Errorf("adapter %s: protocol %d is neither %d nor %d", m.ID, m.Protocol, PaymentProtocol, Protocol2)
	case m.Category == Payments && m.Protocol != PaymentProtocol:
		return fmt.Errorf("adapter %s: a payment adapter speaks protocol %d", m.ID, PaymentProtocol)
	case m.Category == Tools && m.Protocol == PaymentProtocol:
		return fmt.Errorf("adapter %s: a tool cannot speak protocol %d, older panels would take it for a payment method", m.ID, PaymentProtocol)
	case m.Image != ImageFor(m.Category, m.ID):
		return fmt.Errorf("adapter %s: image must be %s", m.ID, ImageFor(m.Category, m.ID))
	case !versionRe.MatchString(m.MinPanel):
		return fmt.Errorf("adapter %s: min_panel %q is not x.y.z[.w][-pre]", m.ID, m.MinPanel)
	case !strings.HasPrefix(m.Homepage, "https://"):
		return fmt.Errorf("adapter %s: homepage must be an https URL", m.ID)
	}
	return m.checkProtocol()
}

// checkProtocol is what the panel and the host check of the protocol fields before they
// offer an entry (Entry.normalize in mikan's internal/panel/addons, normalize in its
// installer/src/addon.rs): an entry they would drop is refused here, never published.
func (m Manifest) checkProtocol() error {
	if m.Protocol == PaymentProtocol {
		// The panel takes protocol 1 for kind payment, mode http; the catalog writes neither,
		// so a payment adapter's entry stays as it always was.
		if m.Kind != "" || m.Mode != "" || m.Permissions != nil || m.Resources != (Resources{}) {
			return fmt.Errorf("adapter %s: protocol %d takes no kind, mode, permissions or resources", m.ID, PaymentProtocol)
		}
		return nil
	}
	if !slices.Contains(Kinds, m.Kind) {
		return fmt.Errorf("adapter %s: kind %q is not %s", m.ID, m.Kind, strings.Join(Kinds, ", "))
	}
	if m.Mode != "" && !slices.Contains(Modes, m.Mode) {
		return fmt.Errorf("adapter %s: mode %q is not %s", m.ID, m.Mode, strings.Join(Modes, " or "))
	}
	seen := map[string]bool{}
	for _, p := range m.Permissions {
		if !slices.Contains(Permissions, p) {
			return fmt.Errorf("adapter %s: unknown permission %q", m.ID, p)
		}
		if seen[p] {
			return fmt.Errorf("adapter %s: permission %q is listed twice", m.ID, p)
		}
		seen[p] = true
	}
	if mem := m.Resources.MemMB; mem != 0 && (mem < MinMemMB || mem > MaxMemMB) {
		return fmt.Errorf("adapter %s: resources.mem_mb %d is not %d to %d (or 0, the host's default)", m.ID, mem, MinMemMB, MaxMemMB)
	}
	return nil
}

// Build makes the index from the manifests and the digests of their pushed images, one
// digest per adapter, sorted by id.
func Build(manifests []Manifest, digests map[string]string, updated time.Time) (Index, error) {
	idx := Index{Version: Format, Updated: updated.UTC().Truncate(time.Second), Adapters: []Entry{}}
	for _, m := range manifests {
		d, ok := digests[m.ID]
		if !ok {
			return idx, fmt.Errorf("no digest for adapter %s", m.ID)
		}
		idx.Adapters = append(idx.Adapters, m.entry(d))
	}
	if len(digests) != len(manifests) {
		return idx, errors.New("a digest is given for an adapter that does not exist")
	}
	slices.SortFunc(idx.Adapters, func(a, b Entry) int { return strings.Compare(a.ID, b.ID) })
	return idx, idx.Check()
}

// Check is what the panel expects of an index.
func (idx Index) Check() error {
	if idx.Version != Format {
		return fmt.Errorf("catalog: format version %d", idx.Version)
	}
	seen := map[string]bool{}
	for _, e := range idx.Adapters {
		m := e.manifest()
		if m.Category == "" {
			m.Category = Payments // the catalogs from before the packages
		}
		if err := m.Check(); err != nil {
			return err
		}
		if !digestRe.MatchString(e.Digest) {
			return fmt.Errorf("adapter %s: digest %q is not sha256:<64 hex>", e.ID, e.Digest)
		}
		if seen[e.ID] {
			return fmt.Errorf("adapter %s is listed twice", e.ID)
		}
		seen[e.ID] = true
	}
	return nil
}

// Sign returns the base64 Ed25519 signature of data, the contents of index.json.sig.
func Sign(data []byte, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))
}

// SignIn returns the signature of data in context, the contents of a .sig2.
func SignIn(context string, data []byte, key ed25519.PrivateKey) string {
	return Sign(append([]byte(context), data...), key)
}

// VerifyIn checks a signature made in context over data by pub.
func VerifyIn(context string, data []byte, sig string, pub ed25519.PublicKey) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(context), data...), raw) {
		return ErrSignature
	}
	return nil
}

// Open checks the catalog's signature (index.json.sig2) over the exact bytes of index.json in
// the catalog's context, then decodes and checks the index.
func Open(data []byte, sig string, pub ed25519.PublicKey) (Index, error) {
	if err := VerifyIn(Context, data, sig, pub); err != nil {
		return Index{}, err
	}
	var idx Index
	if err := decodeStrict(data, &idx); err != nil {
		return idx, fmt.Errorf("catalog: %w", err)
	}
	return idx, idx.Check()
}

// Verify checks the release key's signature over the exact bytes of index.json (index.json.sig,
// LegacyKey), then decodes and checks the index.
func Verify(data []byte, sig string, pub ed25519.PublicKey) (Index, error) {
	var idx Index
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, raw) {
		return idx, ErrSignature
	}
	if err := decodeStrict(data, &idx); err != nil {
		return idx, fmt.Errorf("catalog: %w", err)
	}
	return idx, idx.Check()
}

// Key decodes a raw Ed25519 public key in base64.
func Key(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("catalog: bad public key")
	}
	return raw, nil
}

// PrivateKey reads a PEM PKCS#8 Ed25519 private key, as in MARKETPLACE_SIGNING_KEY.
func PrivateKey(pemText string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("signing key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key: not an Ed25519 key")
	}
	return priv, nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
