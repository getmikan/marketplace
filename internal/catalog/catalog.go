// Package catalog is the signed list of adapters the panel offers (index.json) and the
// adapter.json each adapter directory describes itself with.
//
// index.json is signed like the panel's release manifest: .sig holds
// base64(ed25519.Sign(key, the file's exact bytes)), and the panel and the host trust it
// only with the release key whose public half is PublicKey.
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
	"sort"
	"strings"
	"time"
)

// PublicKey is the public half of the mikan release key (raw Ed25519, base64): the same
// key the panel and the host verify the catalog with.
const PublicKey = "Z3wSIPBSaJxh5CsGO8eINI0aM0kyrQ46EcJSNeH85W8="

// Format is the index.json format version ("version" in the file).
const Format = 1

// ImagePrefix is where adapter images are published: ImagePrefix + id.
const ImagePrefix = "ghcr.io/getmikan/adapter-"

// Manifest is an adapter's adapter.json: its catalog entry without the image digest.
type Manifest struct {
	ID          string            `json:"id"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Version     string            `json:"version"`
	Protocol    int               `json:"protocol"`
	Image       string            `json:"image"`
	MinPanel    string            `json:"min_panel"`
	Homepage    string            `json:"homepage"`
}

// Entry is one adapter in index.json.
type Entry struct {
	ID          string            `json:"id"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Version     string            `json:"version"`
	Protocol    int               `json:"protocol"`
	Image       string            `json:"image"`
	Digest      string            `json:"digest"`
	MinPanel    string            `json:"min_panel"`
	Homepage    string            `json:"homepage"`
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
	versionRe    = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)
	digestRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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
	case m.Name["ru"] == "" || m.Name["en"] == "" || m.Description["ru"] == "" || m.Description["en"] == "":
		return fmt.Errorf("adapter %s: name and description need ru and en", m.ID)
	case !versionRe.MatchString(m.Version):
		return fmt.Errorf("adapter %s: version %q is not x.y.z", m.ID, m.Version)
	case m.Protocol < 1:
		return fmt.Errorf("adapter %s: protocol %d", m.ID, m.Protocol)
	case m.Image != ImagePrefix+m.ID:
		return fmt.Errorf("adapter %s: image must be %s%s", m.ID, ImagePrefix, m.ID)
	case !versionRe.MatchString(m.MinPanel):
		return fmt.Errorf("adapter %s: min_panel %q is not x.y.z", m.ID, m.MinPanel)
	case !strings.HasPrefix(m.Homepage, "https://"):
		return fmt.Errorf("adapter %s: homepage must be an https URL", m.ID)
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
		idx.Adapters = append(idx.Adapters, Entry{ID: m.ID, Name: m.Name, Description: m.Description, Version: m.Version,
			Protocol: m.Protocol, Image: m.Image, Digest: d, MinPanel: m.MinPanel, Homepage: m.Homepage})
	}
	if len(digests) != len(manifests) {
		return idx, errors.New("a digest is given for an adapter that does not exist")
	}
	sort.Slice(idx.Adapters, func(i, j int) bool { return idx.Adapters[i].ID < idx.Adapters[j].ID })
	return idx, idx.Check()
}

// Check is what the panel expects of an index.
func (idx Index) Check() error {
	if idx.Version != Format {
		return fmt.Errorf("catalog: format version %d", idx.Version)
	}
	seen := map[string]bool{}
	for _, e := range idx.Adapters {
		m := Manifest{ID: e.ID, Name: e.Name, Description: e.Description, Version: e.Version, Protocol: e.Protocol,
			Image: e.Image, MinPanel: e.MinPanel, Homepage: e.Homepage}
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

// Verify checks the signature over the exact bytes of index.json, then decodes and
// checks the index.
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
