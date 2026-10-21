// Package community is the registry of community addons (getmikan/marketplace-community):
// addons of third-party authors, which mikan lists and does not vouch for. The registry holds
// a snapshot of each one, addons/<owner>/<id>.json, taken from the latest release of the
// author's repository by the indexer (cmd/community), and revoked.json, the addons mikan took
// out by hand. index.json is all of them in one file, signed with the catalog's key: the panel
// reads it as it reads the catalog and never goes to the authors' hosts for it.
//
// An author's release carries what a panel reads from a third-party source (mikan's
// internal/panel/addons/sources.go): mikan-addon.json, one entry or {title, key, adapters},
// and optionally its .sig, base64(ed25519.Sign(the author's key, the file's bytes)). The
// checks here are the panel's; the panel makes them again on its side.
package community

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/getmikan/marketplace/internal/catalog"
)

// Format is the version of index.json ("version" in the file).
const Format = 1

// Topic is the GitHub topic an author puts on a repository to be found; NoIndex keeps a
// repository out whatever else it has.
const (
	Topic   = "mikan-addon"
	NoIndex = "noindex"
)

// MaxEntries bounds what one repository may list, as the panel bounds a source.
const MaxEntries = 16

// Permissions an addon may ask for: the panel's list (internal/panel/addons of mikan), wider
// than the catalog's, whose own tools need less. Wide are the ones that reach every subscriber:
// a snapshot that newly asks for one waits for a review.
var (
	Permissions = []string{"bot", "users:read", "users:write", "users:all", "users:grant", "billing:invoice", "events", "kv", "ui"}
	Wide        = []string{"users:all", "users:grant"}
)

// Reserved ids are never a community addon's: the panel hands the bot slot to telegram by
// itself.
var Reserved = []string{"telegram"}

// Resources an addon asks the host for.
type Resources struct {
	MemMB int `json:"mem_mb,omitempty"`
}

// Entry is an addon as the panel installs it; the names are the panel's (addons.Entry).
type Entry struct {
	ID          string            `json:"id"`
	Name        map[string]string `json:"name"`
	Description map[string]string `json:"description"`
	Version     string            `json:"version"`
	Protocol    int               `json:"protocol"`
	Kind        string            `json:"kind"`
	Mode        string            `json:"mode"`
	Permissions []string          `json:"permissions"`
	Resources   Resources         `json:"resources,omitzero"`
	Image       string            `json:"image"`
	Digest      string            `json:"digest"`
	MinPanel    string            `json:"min_panel,omitempty"`
	Homepage    string            `json:"homepage,omitempty"`
}

// Prior is a build of an addon the registry had before.
type Prior struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Addon is one snapshot, addons/<owner>/<id>.json. Repo is github.com/<owner>/<repo> as
// GitHub spells it; RepoID follows the repository through a rename or a transfer. Key is the
// author's public key (base64) the release was signed with, "" for an unsigned one: a later
// release signed otherwise waits for a review.
type Addon struct {
	Entry
	Repo   string `json:"repo"`
	RepoID int64  `json:"repo_id"`
	Key    string `json:"key,omitempty"`
	Stars  int    `json:"stars"`
	// Downloads is how many times the image was pulled, as the page of its GitHub package
	// counts it, to two significant digits (RoundCount): no telemetry of panels, and no
	// commit with every pull. 0 for an image elsewhere.
	Downloads int    `json:"downloads,omitempty"`
	Previous  *Prior `json:"previous,omitempty"`
	AddedAt   int64  `json:"added_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Owner is the directory the snapshot sits in: the repository's owner, lowercase.
func (a Addon) Owner() string {
	parts := strings.Split(a.Repo, "/")
	if len(parts) != 3 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// Path is where the snapshot sits in the registry.
func (a Addon) Path() string { return "addons/" + a.Owner() + "/" + a.ID + ".json" }

// Revoked is an addon mikan took out of the registry, by id or by repository (every addon of
// it). A panel shows it to the admin who has it installed and installs nothing of it again.
type Revoked struct {
	ID     string `json:"id,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Reason string `json:"reason"`
	At     string `json:"at"`
}

// Index is index.json.
type Index struct {
	Version int       `json:"version"`
	Updated time.Time `json:"updated"`
	Addons  []Addon   `json:"addons"`
	Revoked []Revoked `json:"revoked"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	digestRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)
	panelRe   = regexp.MustCompile(`^\d+\.\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	repoRe    = regexp.MustCompile(`^github\.com/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// The image grammar the panel and the host accept (addons.ValidImage of mikan).
	hostRe      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::[0-9]{1,5})?$`)
	componentRe = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
)

// validImage is an image without a tag, [host[:port]/]path/name, on a public registry: the
// root host pulls it on the author's word.
func validImage(r string) bool {
	if r == "" || len(r) > 255 {
		return false
	}
	parts := strings.Split(r, "/")
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		if !hostRe.MatchString(parts[0]) || !publicHost(parts[0]) {
			return false
		}
		parts = parts[1:]
	}
	for _, p := range parts {
		if !componentRe.MatchString(p) {
			return false
		}
	}
	return true
}

// publicHost is the panel's proto.PublicHost, narrowed to what an image may name.
func publicHost(h string) bool {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || !strings.Contains(h, ".") {
		return false
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return true
	}
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// Check says why an entry is not one a panel would install from a third party, "" when it is
// one; on success the entry is clean (mode filled in, texts trimmed, a homepage that is no
// https link dropped).
func (e *Entry) Check() string {
	switch {
	case !idRe.MatchString(e.ID):
		return "id_invalid"
	case slices.Contains(Reserved, e.ID):
		return "id_taken"
	case e.Protocol == catalog.PaymentProtocol || e.Kind == "payment":
		return "payment"
	case e.Protocol != catalog.Protocol2:
		return "invalid"
	}
	if e.Mode == "" {
		e.Mode = "http"
	}
	if !slices.Contains(catalog.Kinds, e.Kind) || !slices.Contains(catalog.Modes, e.Mode) {
		return "invalid"
	}
	seen := map[string]bool{}
	for _, p := range e.Permissions {
		if seen[p] || !slices.Contains(Permissions, p) {
			return "invalid"
		}
		seen[p] = true
	}
	if e.Permissions == nil {
		e.Permissions = []string{}
	}
	switch mem := e.Resources.MemMB; {
	case mem != 0 && (mem < catalog.MinMemMB || mem > catalog.MaxMemMB):
		return "invalid"
	case !validImage(e.Image):
		return "image_invalid"
	case !digestRe.MatchString(e.Digest):
		return "digest_invalid"
	case !versionRe.MatchString(e.Version):
		return "version_invalid"
	case e.MinPanel != "" && !panelRe.MatchString(e.MinPanel):
		return "invalid"
	}
	e.Name, e.Description = cleanText(e.Name, 80), cleanText(e.Description, 500)
	if len(e.Name) == 0 {
		return "invalid"
	}
	if u, err := url.Parse(e.Homepage); err != nil || u.Scheme != "https" || u.Host == "" || len(e.Homepage) > 300 {
		e.Homepage = ""
	}
	return ""
}

// cleanText keeps what is readable and short, as the panel does with a source's words.
func cleanText(t map[string]string, maxRunes int) map[string]string {
	out := map[string]string{}
	langs := slices.Sorted(maps.Keys(t))
	for _, lang := range langs {
		if len(out) >= 8 {
			break
		}
		if len(lang) == 0 || len(lang) > 8 {
			continue
		}
		s := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' || !unicode.IsControl(r) && r != utf8.RuneError {
				return r
			}
			return -1
		}, t[lang])
		if r := []rune(s); len(r) > maxRunes {
			s = string(r[:maxRunes])
		}
		if s = strings.TrimSpace(s); s != "" {
			out[lang] = s
		}
	}
	return out
}

// Skip is an entry of an author's release that is not taken, and why.
type Skip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Doc is what an author's release gives: the key it is signed with ("" unsigned), the entries
// that pass, and the ones that do not.
type Doc struct {
	Key     string
	Entries []Entry
	Skipped []Skip
}

var (
	ErrBadFile    = errors.New("community: the release file is not a mikan addon")
	ErrSignature  = errors.New("community: the release signature does not verify")
	ErrKeyNeeded  = errors.New("community: the release is signed but names no key")
	ErrNoEntries  = errors.New("community: nothing in the release can be installed")
	ErrBadSigFile = errors.New("community: the signature is not base64")
)

// ParseDoc reads an author's release file and its signature (nil: none), as the panel reads a
// source: a signature is checked against the key the registry holds for the repository (pin),
// else the key the file names.
func ParseDoc(data, sig []byte, pin string) (Doc, error) {
	var f struct {
		Key      string          `json:"key"`
		Adapters json.RawMessage `json:"adapters"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return Doc{}, fmt.Errorf("%w: %v", ErrBadFile, err)
	}
	var doc Doc
	if sig != nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil {
			return Doc{}, ErrBadSigFile
		}
		for _, k := range []string{pin, f.Key} {
			if pub, err := catalog.Key(strings.TrimSpace(k)); err == nil && ed25519.Verify(pub, data, raw) {
				doc.Key = base64.StdEncoding.EncodeToString(pub)
				break
			}
		}
		switch {
		case doc.Key == "" && pin == "" && f.Key == "":
			return Doc{}, ErrKeyNeeded
		case doc.Key == "":
			return Doc{}, ErrSignature
		}
	}
	var entries []Entry
	if f.Adapters != nil {
		if err := json.Unmarshal(f.Adapters, &entries); err != nil {
			return Doc{}, fmt.Errorf("%w: adapters: %v", ErrBadFile, err)
		}
	} else {
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			return Doc{}, fmt.Errorf("%w: %v", ErrBadFile, err)
		}
		entries = []Entry{e}
	}
	seen := map[string]bool{}
	for _, e := range entries {
		id := cleanLine(e.ID, 40)
		switch reason := e.Check(); {
		case len(doc.Entries) >= MaxEntries:
			doc.Skipped = append(doc.Skipped, Skip{id, "too_many"})
		case reason != "":
			doc.Skipped = append(doc.Skipped, Skip{id, reason})
		case seen[e.ID]:
			doc.Skipped = append(doc.Skipped, Skip{id, "duplicate"})
		default:
			seen[e.ID] = true
			doc.Entries = append(doc.Entries, e)
		}
	}
	if len(doc.Entries) == 0 {
		return doc, ErrNoEntries
	}
	return doc, nil
}

func cleanLine(s string, maxRunes int) string {
	s = strings.Join(strings.FieldsFunc(s, unicode.IsControl), " ")
	if r := []rune(s); len(r) > maxRunes {
		s = string(r[:maxRunes])
	}
	return strings.TrimSpace(s)
}

// Check is what a snapshot must be to be published.
func (a Addon) Check() error {
	e := a.Entry
	if reason := e.Check(); reason != "" {
		return fmt.Errorf("addon %q: %s", a.ID, reason)
	}
	switch {
	case !repoRe.MatchString(a.Repo):
		return fmt.Errorf("addon %s: repo %q is not github.com/<owner>/<repo>", a.ID, a.Repo)
	case a.RepoID <= 0:
		return fmt.Errorf("addon %s: no repo_id", a.ID)
	case a.Key != "" && !validKey(a.Key):
		return fmt.Errorf("addon %s: key is not a base64 Ed25519 public key", a.ID)
	case a.Previous != nil && (!digestRe.MatchString(a.Previous.Digest) || !versionRe.MatchString(a.Previous.Version)):
		return fmt.Errorf("addon %s: previous build is malformed", a.ID)
	case a.AddedAt <= 0 || a.UpdatedAt < a.AddedAt:
		return fmt.Errorf("addon %s: added_at and updated_at", a.ID)
	}
	return nil
}

func validKey(k string) bool {
	_, err := catalogKey(k)
	return err == nil
}

func catalogKey(k string) (ed25519.PublicKey, error) { return catalog.Key(strings.TrimSpace(k)) }

// Check is what a panel expects of the index: every snapshot valid, an id once, no reserved or
// catalog id (official), every revocation naming an id or a repository and saying why.
func (idx Index) Check(official []string) error {
	if idx.Version != Format {
		return fmt.Errorf("community: format version %d", idx.Version)
	}
	seen := map[string]bool{}
	for _, a := range idx.Addons {
		if err := a.Check(); err != nil {
			return err
		}
		if slices.Contains(official, a.ID) {
			return fmt.Errorf("addon %s: the id is the official catalog's", a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("addon %s is listed twice", a.ID)
		}
		seen[a.ID] = true
	}
	for _, r := range idx.Revoked {
		switch {
		case r.ID == "" && r.Repo == "":
			return errors.New("revoked: an entry names neither an id nor a repo")
		case r.ID != "" && !idRe.MatchString(r.ID), r.Repo != "" && !repoRe.MatchString(r.Repo):
			return fmt.Errorf("revoked: %q %q is malformed", r.ID, r.Repo)
		case strings.TrimSpace(r.Reason) == "" || !dateRe.MatchString(r.At):
			return fmt.Errorf("revoked: %s%s needs a reason and a date (YYYY-MM-DD)", r.ID, r.Repo)
		}
	}
	return nil
}

// RevokedFor is the revocation that covers the addon, if any.
func (idx Index) RevokedFor(a Addon) (Revoked, bool) {
	for _, r := range idx.Revoked {
		if r.ID == a.ID || r.Repo != "" && strings.EqualFold(r.Repo, a.Repo) {
			return r, true
		}
	}
	return Revoked{}, false
}

// Build makes the index: the snapshots sorted by id, and the revocations. A revoked addon
// stays out of the list, so no panel offers it; installed, it is still named by revoked.
func Build(addons []Addon, revoked []Revoked, official []string, updated time.Time) (Index, error) {
	idx := Index{Version: Format, Updated: updated.UTC().Truncate(time.Second), Addons: []Addon{}, Revoked: revoked}
	if idx.Revoked == nil {
		idx.Revoked = []Revoked{}
	}
	for _, a := range addons {
		if _, out := idx.RevokedFor(a); !out {
			idx.Addons = append(idx.Addons, a)
		}
	}
	sort.Slice(idx.Addons, func(i, j int) bool { return idx.Addons[i].ID < idx.Addons[j].ID })
	return idx, idx.Check(official)
}

// PublicKey is the public half of the registry's key (raw Ed25519, base64): the same key as
// mikan's internal/release.CommunityKey, which the panel verifies the index with.
const PublicKey = "BKCw8Uf/qo3xSrYL+jwWyEThn/PXxHh0FiJvLDowmdc="

// Context is what the index's signature covers before the file's bytes (mikan's
// internal/release.CommunityContext).
const Context = "mikan community v1\n"

// Sign is the base64 Ed25519 signature of the file, the contents of index.json.sig: the release
// key's, for the panels before 0.5.1.1.
func Sign(data []byte, key ed25519.PrivateKey) string { return catalog.Sign(data, key) }

// SignIn is the registry's signature of the file in its context, the contents of
// index.json.sig2.
func SignIn(data []byte, key ed25519.PrivateKey) string { return catalog.SignIn(Context, data, key) }

var ErrIndexSignature = errors.New("community: bad signature")

// Verify checks the release key's signature over the exact bytes of index.json
// (index.json.sig), then the index.
func Verify(data []byte, sig string, pub ed25519.PublicKey, official []string) (Index, error) {
	var idx Index
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig))
	if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, raw) {
		return idx, ErrIndexSignature
	}
	return decodeIndex(data, official)
}

// Open checks the registry's signature (index.json.sig2) over the exact bytes of index.json in
// its context, then the index.
func Open(data []byte, sig string, pub ed25519.PublicKey, official []string) (Index, error) {
	if catalog.VerifyIn(Context, data, sig, pub) != nil {
		return Index{}, ErrIndexSignature
	}
	return decodeIndex(data, official)
}

// decodeIndex reads a signed index and checks it.
func decodeIndex(data []byte, official []string) (Index, error) {
	var idx Index
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&idx); err != nil {
		return idx, fmt.Errorf("community: %w", err)
	}
	return idx, idx.Check(official)
}

// SameContent says whether two indexes list the same: a release is made only when something
// changed, not for a new time stamp.
func SameContent(a, b Index) bool {
	a.Updated, b.Updated = time.Time{}, time.Time{}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}
