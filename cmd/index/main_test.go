package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/getmikan/marketplace/internal/catalog"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

// throwawayKey sets MARKETPLACE_CATALOG_KEY to a fresh key, with no release key
// (MARKETPLACE_SIGNING_KEY), and returns its public half.
func throwawayKey(t *testing.T) string {
	t.Helper()
	t.Setenv("MARKETPLACE_SIGNING_KEY", "")
	return keyIn(t, "MARKETPLACE_CATALOG_KEY")
}

// keyIn sets the variable to a fresh key and returns its public half.
func keyIn(t *testing.T, name string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	return base64.StdEncoding.EncodeToString(pub)
}

func runOK(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatalf("index %s: %v", strings.Join(args, " "), err)
	}
	return out.String()
}

func runFails(t *testing.T, want string, args ...string) {
	t.Helper()
	err := run(args, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("index %s: %v, want an error with %q", strings.Join(args, " "), err, want)
	}
}

// realIndex is the catalog of the real packages, every image at digestA.
func realIndex(t *testing.T) ([]catalog.Manifest, catalog.Index) {
	t.Helper()
	ms, err := manifests("../..")
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for _, m := range ms {
		digests[m.ID] = digestA
	}
	idx, err := catalog.Build(ms, digests, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ms, idx
}

// digestFlags is a -digest for every real adapter: digestA for yookassa, digestB for the rest.
var digestFlags = []string{"-digest", "yookassa=" + digestA, "-digest", "cardlink=" + digestB, "-digest", "cryptobot=" + digestB,
	"-digest", "platega=" + digestB, "-digest", "rollypay=" + digestB, "-digest", "telegram=" + digestB}

// version is the version the real adapters are at.
func version(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../payments/yookassa/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := catalog.ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	return m.Version
}

// The real packages: the payment adapters in payments/ and the tools in tools/, with their images.
func TestListRealAdapters(t *testing.T) {
	var got []listed
	if err := json.Unmarshal([]byte(runOK(t, "list", "-root", "../..")), &got); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, l := range got {
		ids = append(ids, l.ID)
		category, prefix := "payments", "adapter-"
		if l.ID == "telegram" {
			category, prefix = "tools", "tool-"
		}
		if l.Dir != category+"/"+l.ID || l.Image != "ghcr.io/getmikan/"+prefix+l.ID || l.Version == "" {
			t.Errorf("%s: %+v", l.ID, l)
		}
	}
	if strings.Join(ids, ",") != "cardlink,cryptobot,platega,rollypay,yookassa,telegram" {
		t.Fatalf("index list: %v", ids)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub := throwawayKey(t)
	out := t.TempDir()
	v := version(t)
	runOK(t, append([]string{"build", "-root", "../..", "-out", out}, digestFlags...)...)
	file := filepath.Join(out, "index.json")
	got := runOK(t, "verify", "-key", pub, file)
	if !strings.Contains(got, "ok: payments cryptobot ") || !strings.Contains(got, " ghcr.io/getmikan/adapter-cryptobot@"+digestB) ||
		!strings.Contains(got, "ok: payments yookassa "+v+" ghcr.io/getmikan/adapter-yookassa@"+digestA) {
		t.Fatalf("verify: %s", got)
	}

	// The signature is base64(ed25519.Sign(key, the catalog's context + the exact bytes)) in
	// index.json.sig2, as the panel checks it; without the release key there is no .sig.
	data, _ := os.ReadFile(file)
	sig, _ := os.ReadFile(file + catalog.SigSuffix)
	key, _ := catalog.Key(pub)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(key, append([]byte(catalog.Context), data...), raw) {
		t.Fatal("the signature does not verify over the context and the file's bytes")
	}
	if ed25519.Verify(key, data, raw) {
		t.Fatal("the signature holds over the bytes alone")
	}
	if _, err := os.Stat(file + ".sig"); err == nil {
		t.Fatal("index.json.sig without the release key")
	}
	idx, err := catalog.Open(data, string(sig), key)
	if err != nil || idx.Version != 1 || len(idx.Adapters) != 6 || idx.Adapters[5].Digest != digestA || idx.Adapters[5].MinPanel != "0.4.3" ||
		idx.Adapters[5].Category != "payments" || !bytes.Contains(data, []byte(`"category": "payments"`)) {
		t.Fatalf("index: %v %+v", err, idx)
	}

	// The release key does not verify a throwaway signature.
	runFails(t, "bad signature", "verify", file)

	// One changed byte, and it fails.
	tampered := bytes.Replace(data, []byte(digestA), []byte(digestB), 1)
	if err := os.WriteFile(file, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	runFails(t, "bad signature", "verify", "-key", pub, file)
}

// While MARKETPLACE_SIGNING_KEY is given, the release key's index.json.sig is made too, over
// the bytes alone as the panels before 0.5.1.1 read it, and verify checks it with the
// release key's public half; a catalog with only that signature still reads as a previous one.
func TestLegacySignature(t *testing.T) {
	pub := throwawayKey(t)
	legacy := keyIn(t, "MARKETPLACE_SIGNING_KEY")
	out := t.TempDir()
	runOK(t, append([]string{"build", "-root", "../..", "-out", out}, digestFlags...)...)
	file := filepath.Join(out, "index.json")
	data, _ := os.ReadFile(file)
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		t.Fatal("no index.json.sig with the release key given")
	}
	key, _ := catalog.Key(legacy)
	if _, err := catalog.Verify(data, string(sig), key); err != nil {
		t.Fatalf("index.json.sig: %v", err)
	}
	runOK(t, "verify", "-key", pub, "-legacy-key", legacy, file)
	runFails(t, "index.json.sig", "verify", "-key", pub, file)
	if err := os.Remove(file + catalog.SigSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := readCatalog(file, pub, legacy); err != nil {
		t.Fatalf("a catalog from before the catalog's key: %v", err)
	}
	if _, err := readCatalog(file, pub, ""); err == nil {
		t.Fatal("a catalog without index.json.sig2 read without the release key")
	}
}

func TestBuildRefuses(t *testing.T) {
	throwawayKey(t)
	out := t.TempDir()
	base := []string{"build", "-root", "../..", "-out", out}
	runFails(t, "no digest for adapter", append(base, "-digest", "yookassa="+digestA)...)
	runFails(t, "does not exist", append(slices.Concat(base, digestFlags), "-digest", "stripe="+digestA)...)
	runFails(t, "two digests", append(base, "-digest", "yookassa="+digestA, "-digest", "yookassa="+digestB)...)
	runFails(t, "digest", append(slices.Concat(base, digestFlags[2:]), "-digest", "yookassa=sha256:abc")...)
	t.Setenv("MARKETPLACE_CATALOG_KEY", "")
	runFails(t, "MARKETPLACE_CATALOG_KEY", slices.Concat(base, digestFlags)...)
	if _, err := os.Stat(filepath.Join(out, "index.json")); err == nil {
		t.Fatal("a refused build wrote index.json")
	}
}

func TestManifestChecks(t *testing.T) {
	root := t.TempDir()
	write := func(category, id, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, category, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, category, id, "adapter.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runFails(t, "no adapters", "list", "-root", root)
	ok := `{"id":"demo","category":"payments","name":{"ru":"Демо","en":"Demo"},"description":{"ru":"д","en":"d"},"version":"1.0.0","protocol":1,` +
		`"image":"ghcr.io/getmikan/adapter-demo","min_panel":"0.4.3","homepage":"https://example.com"}`
	write("payments", "demo", ok)
	runOK(t, "list", "-root", root)

	for name, body := range map[string]string{
		"unknown field":    strings.Replace(ok, `"protocol":1`, `"protocol":1,"extra":true`, 1),
		"foreign image":    strings.Replace(ok, "ghcr.io/getmikan/adapter-demo", "docker.io/evil/demo", 1),
		"no en name":       strings.Replace(ok, `"en":"Demo"`, `"de":"Demo"`, 1),
		"bad version":      strings.Replace(ok, `"version":"1.0.0"`, `"version":"latest"`, 1),
		"http homepage":    strings.Replace(ok, "https://example.com", "http://example.com", 1),
		"no category":      strings.Replace(ok, `"category":"payments",`, "", 1),
		"unknown category": strings.Replace(ok, `"category":"payments"`, `"category":"games"`, 1),
		"payment protocol": strings.Replace(ok, `"protocol":1`, `"protocol":2`, 1),
		"tool image":       strings.Replace(ok, "ghcr.io/getmikan/adapter-demo", "ghcr.io/getmikan/tool-demo", 1),
	} {
		write("payments", "demo", body)
		if err := run([]string{"list", "-root", root}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	write("payments", "demo", ok)
	write("payments", "other", ok) // id "demo" in the directory "other"
	runFails(t, "but the directory is", "list", "-root", root)

	// Two adapters at different versions are valid.
	other := strings.ReplaceAll(strings.Replace(ok, `"version":"1.0.0"`, `"version":"1.0.1"`, 1), "demo", "other")
	write("payments", "other", other)
	runOK(t, "list", "-root", root)

	// A tool: in tools/, its own image, never the payment protocol (older panels would
	// offer it as a payment method).
	tool := strings.NewReplacer(`"category":"payments"`, `"category":"tools"`, `"protocol":1`, `"protocol":2,"kind":"bot"`,
		"adapter-demo", "tool-tg", `"id":"demo"`, `"id":"tg"`).Replace(ok)
	write("tools", "tg", tool)
	var got []listed
	if err := json.Unmarshal([]byte(runOK(t, "list", "-root", root)), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != (listed{ID: "tg", Version: "1.0.0", Dir: "tools/tg", Image: "ghcr.io/getmikan/tool-tg"}) {
		t.Fatalf("list: %+v", got)
	}
	write("tools", "tg", strings.Replace(tool, `"protocol":2`, `"protocol":1`, 1))
	runFails(t, "older panels", "list", "-root", root)
	write("tools", "tg", strings.Replace(tool, "tool-tg", "adapter-tg", 1))
	runFails(t, "image must be ghcr.io/getmikan/tool-tg", "list", "-root", root)
	write("tools", "tg", tool)

	// A payment adapter in tools/, and one id in two packages.
	write("tools", "demo", ok)
	runFails(t, "but it is in tools/", "list", "-root", root)
	if err := os.RemoveAll(filepath.Join(root, "tools", "demo")); err != nil {
		t.Fatal(err)
	}
	write("tools", "other", strings.ReplaceAll(tool, "tg", "other"))
	runFails(t, "is taken in payments/", "list", "-root", root)
}

// A catalog from before the packages has no categories: its entries are payment adapters.
func TestIndexWithoutCategories(t *testing.T) {
	_, idx := realIndex(t)
	// Such a catalog held payment adapters only.
	idx.Adapters = slices.DeleteFunc(idx.Adapters, func(e catalog.Entry) bool { return e.Category != "payments" })
	for i := range idx.Adapters {
		idx.Adapters[i].Category = ""
	}
	if err := idx.Check(); err != nil {
		t.Fatalf("an index without categories: %v", err)
	}
	idx.Adapters[0].Category = "games"
	if err := idx.Check(); err == nil {
		t.Fatal("an unknown category passed")
	}
}

func TestReleasePlanOnlyChangedAdapter(t *testing.T) {
	ms, prev := realIndex(t)
	for i := range ms {
		if ms[i].ID == "rollypay" {
			ms[i].Version = "9.0.0"
		}
	}
	p, err := makeReleasePlan("../..", ms, prev, []string{"payments/rollypay/rollypay.go", "README.md"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Build) != 1 || p.Build[0].ID != "rollypay" || p.Build[0].Version != "9.0.0" || p.Build[0].Dir != "payments/rollypay" ||
		p.Build[0].Image != "ghcr.io/getmikan/adapter-rollypay" || len(p.Reuse) != 5 {
		t.Fatalf("plan: %+v", p)
	}
	for id, digest := range p.Reuse {
		if id == "rollypay" || digest != digestA {
			t.Fatalf("reuse: %+v", p.Reuse)
		}
	}
	for i := range ms {
		if ms[i].ID == "rollypay" {
			ms[i].Version = prev.Adapters[3].Version
		}
	}
	if _, err := makeReleasePlan("../..", ms, prev, []string{"payments/rollypay/rollypay.go"}); err == nil || !strings.Contains(err.Error(), "bump its version") {
		t.Fatalf("unchanged version: %v", err)
	}
	if _, err := makeReleasePlan("../..", ms, prev, []string{"internal/adapter/server.go"}); err == nil || !strings.Contains(err.Error(), "bump its version") {
		t.Fatalf("shared code: %v", err)
	}
	// The move from adapters/ to payments/ is a change of every adapter.
	if _, err := makeReleasePlan("../..", ms, prev, []string{"adapters/rollypay/rollypay.go", "payments/rollypay/rollypay.go"}); err == nil || !strings.Contains(err.Error(), "bump its version") {
		t.Fatalf("the move: %v", err)
	}
	if p, err := makeReleasePlan("../..", ms, prev, []string{"payments/rollypay/README.md", "payments/rollypay/rollypay_test.go"}); err != nil || len(p.Build) != 0 {
		t.Fatalf("documentation and tests: %+v, %v", p, err)
	}
	// The community registry's indexer is in no image.
	if p, err := makeReleasePlan("../..", ms, prev, []string{"cmd/community/main.go", "internal/community/sync.go"}); err != nil || len(p.Build) != 0 {
		t.Fatalf("the community indexer: %+v, %v", p, err)
	}
	for i := range ms {
		if ms[i].ID == "rollypay" {
			ms[i].Version = "1.0.2"
		}
	}
	if _, err := makeReleasePlan("../..", ms, prev, []string{"payments/rollypay/rollypay.go"}); err == nil || !strings.Contains(err.Error(), "must be newer") {
		t.Fatalf("downgrade: %v", err)
	}
}

func TestCompareVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.0.10", "1.0.9", 1},
		{"2.0.0", "10.0.0", -1},
		{"1.0.0-rc.10", "1.0.0-rc.9", 1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0", "1.0.0", 0},
		{"0.5.1.0", "0.5.1.0-rc.6", 1},
		{"0.5.1.0-rc.10", "0.5.1.0-rc.9", 1},
		{"0.5.1.1", "0.5.1", 1},
		{"0.5.1", "0.5.1.0", 0},
		{"0.5.2", "0.5.1.9", 1},
	} {
		if got := compareVersion(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersion(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBuildWithReusedDigests(t *testing.T) {
	throwawayKey(t)
	ms, err := manifests("../..")
	if err != nil {
		t.Fatal(err)
	}
	p := releasePlan{Build: []listed{}, Reuse: map[string]string{}}
	for _, m := range ms {
		if m.ID == "rollypay" {
			p.Build = append(p.Build, listed{ID: m.ID, Version: m.Version, Dir: dir(m), Image: m.Image})
		} else {
			p.Reuse[m.ID] = digestA
		}
	}
	file := filepath.Join(t.TempDir(), "plan.json")
	data, _ := json.Marshal(p)
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	runOK(t, "build", "-root", "../..", "-plan", file, "-digest", "rollypay="+digestB, "-out", out)
	indexData, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx catalog.Index
	if err := json.Unmarshal(indexData, &idx); err != nil {
		t.Fatal(err)
	}
	for _, e := range idx.Adapters {
		want := digestA
		if e.ID == "rollypay" {
			want = digestB
		}
		if e.Digest != want {
			t.Fatalf("%s digest: %s", e.ID, e.Digest)
		}
	}
	runFails(t, "unexpected pushed digest", "build", "-root", "../..", "-plan", file, "-digest", "yookassa="+digestB, "-out", out)
	runFails(t, "no digest for adapter rollypay", "build", "-root", "../..", "-plan", file, "-out", out)
}

// The telegram tool: protocol 2 with the fields the panel reads, in tools/.
func TestTelegramEntry(t *testing.T) {
	ms, err := manifests("../..")
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for _, m := range ms {
		digests[m.ID] = digestA
	}
	idx, err := catalog.Build(ms, digests, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range idx.Adapters {
		if e.ID != "telegram" {
			if e.Protocol != 1 || e.Kind != "" || e.Mode != "" || e.Permissions != nil || e.Resources != (catalog.Resources{}) {
				t.Errorf("%s: %+v", e.ID, e)
			}
			continue
		}
		if e.Category != "tools" || e.Protocol != 2 || e.Kind != "bot" || e.Mode != "client" || e.Resources.MemMB != 128 ||
			strings.Join(e.Permissions, ",") != "bot,users:read,users:write,billing:invoice,events,kv" ||
			e.Image != "ghcr.io/getmikan/tool-telegram" || e.MinPanel != e.Version {
			t.Errorf("telegram: %+v", e)
		}
		return
	}
	t.Fatal("no telegram in the index")
}

func TestOwnInputsOnly(t *testing.T) {
	root := t.TempDir()
	for name, tc := range map[string]struct {
		dockerfile string
		want       bool
	}{
		"the shared code":  {"FROM golang AS build\nCOPY go.mod ./\nCOPY internal/ internal/\nCOPY payments/x/ payments/x/\n", false},
		"a continued line": {"FROM golang\nCOPY --chown=1:1 \\n  internal/ \\n  /src/\n", false},
		"the JSON form":    {"FROM golang\nCOPY [\"payments/x/a\", \"/a\"]\n", false},
		"its own files":    {"FROM golang\ncopy payments/x/main.go ./\nADD payments/x /src\n", true},
		"another source":   {"FROM golang AS build\nARG VERSION\nRUN git clone https://example.com/a.git .\nADD https://example.com/a.tar /a\nFROM scratch\nCOPY --from=build /out/a /a\n", true},
		"a way out":        {"FROM golang\nCOPY payments/x/../../internal /i\n", false},
	} {
		dir := filepath.Join(root, "payments", "x")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(tc.dockerfile), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := ownInputsOnly(root, "payments/x"); err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
	if _, err := ownInputsOnly(root, "payments/none"); err == nil {
		t.Error("a package without a Dockerfile passed")
	}
}

// The telegram tool builds mikan's source: the shared code of this repository is no input
// of its image, so a change there does not ask for a new telegram version (which must be a
// mikan release).
func TestReleasePlanSelfContainedTool(t *testing.T) {
	ms, prev := realIndex(t)
	bumped := slices.Clone(ms)
	for i := range bumped {
		if bumped[i].Category == "payments" {
			bumped[i].Version = "9.0.0"
		}
	}
	p, err := makeReleasePlan("../..", bumped, prev, []string{"go.mod", "internal/adapter/server.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Build) != 5 || p.Reuse["telegram"] != digestA || len(p.Reuse) != 1 {
		t.Fatalf("shared code: %+v", p)
	}
	if _, err := makeReleasePlan("../..", ms, prev, []string{"tools/telegram/Dockerfile"}); err == nil || !strings.Contains(err.Error(), "telegram changed") {
		t.Fatalf("the telegram Dockerfile: %v", err)
	}
	for i := range ms {
		if ms[i].ID == "telegram" {
			ms[i].Version = "0.5.1.0"
		}
	}
	p, err = makeReleasePlan("../..", ms, prev, []string{"tools/telegram/adapter.json"})
	if err != nil || len(p.Build) != 1 || p.Build[0] != (listed{ID: "telegram", Version: "0.5.1.0", Dir: "tools/telegram", Image: "ghcr.io/getmikan/tool-telegram"}) {
		t.Fatalf("a new mikan release: %+v, %v", p, err)
	}
}
