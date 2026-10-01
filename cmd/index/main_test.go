package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getmikan/marketplace/internal/catalog"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

// throwawayKey sets MARKETPLACE_SIGNING_KEY to a fresh key and returns its public half.
func throwawayKey(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARKETPLACE_SIGNING_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
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

// version is the version the real adapters are at.
func version(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../adapters/yookassa/adapter.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := catalog.ParseManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	return m.Version
}

// The real adapters/ directory: all adapters, one version.
func TestListRealAdapters(t *testing.T) {
	want := `["cryptobot","platega","rollypay","yookassa"]` + "\n"
	for _, args := range [][]string{{"list", "-adapters", "../../adapters"}, {"list", "-adapters", "../../adapters", "-version", version(t)}} {
		if got := runOK(t, args...); got != want {
			t.Fatalf("index %v: %q", args, got)
		}
	}
	runFails(t, "but the release is 0.0.0-never", "list", "-adapters", "../../adapters", "-version", "0.0.0-never")
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub := throwawayKey(t)
	out := t.TempDir()
	v := version(t)
	runOK(t, "build", "-adapters", "../../adapters", "-version", v, "-digest", "yookassa="+digestA, "-digest", "cryptobot="+digestB, "-digest", "platega="+digestB, "-digest", "rollypay="+digestB, "-out", out)
	file := filepath.Join(out, "index.json")
	got := runOK(t, "verify", "-key", pub, file)
	if !strings.Contains(got, "ok: cryptobot "+v+" ghcr.io/getmikan/adapter-cryptobot@"+digestB) ||
		!strings.Contains(got, "ok: yookassa "+v+" ghcr.io/getmikan/adapter-yookassa@"+digestA) {
		t.Fatalf("verify: %s", got)
	}

	// The signature is base64(ed25519.Sign(key, exact bytes)), as the panel checks it.
	data, _ := os.ReadFile(file)
	sig, _ := os.ReadFile(file + ".sig")
	key, _ := catalog.Key(pub)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(key, data, raw) {
		t.Fatal("the signature does not verify over the file's bytes")
	}
	idx, err := catalog.Verify(data, string(sig), key)
	if err != nil || idx.Version != 1 || len(idx.Adapters) != 4 || idx.Adapters[3].Digest != digestA || idx.Adapters[3].MinPanel != "0.4.3" {
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

func TestBuildRefuses(t *testing.T) {
	throwawayKey(t)
	out := t.TempDir()
	base := []string{"build", "-adapters", "../../adapters", "-version", version(t), "-out", out}
	runFails(t, "-version is required", "build", "-adapters", "../../adapters", "-digest", "yookassa="+digestA, "-digest", "cryptobot="+digestB, "-digest", "platega="+digestB, "-digest", "rollypay="+digestB)
	runFails(t, "no digest for adapter", append(base, "-digest", "yookassa="+digestA)...)
	runFails(t, "does not exist", append(base, "-digest", "yookassa="+digestA, "-digest", "cryptobot="+digestB, "-digest", "platega="+digestB, "-digest", "rollypay="+digestB, "-digest", "stripe="+digestA)...)
	runFails(t, "two digests", append(base, "-digest", "yookassa="+digestA, "-digest", "yookassa="+digestB)...)
	runFails(t, "digest", append(base, "-digest", "yookassa=sha256:abc", "-digest", "cryptobot="+digestB, "-digest", "platega="+digestB, "-digest", "rollypay="+digestB)...)
	t.Setenv("MARKETPLACE_SIGNING_KEY", "")
	runFails(t, "MARKETPLACE_SIGNING_KEY", append(base, "-digest", "yookassa="+digestA, "-digest", "cryptobot="+digestB, "-digest", "platega="+digestB, "-digest", "rollypay="+digestB)...)
	if _, err := os.Stat(filepath.Join(out, "index.json")); err == nil {
		t.Fatal("a refused build wrote index.json")
	}
}

func TestManifestChecks(t *testing.T) {
	dir := t.TempDir()
	write := func(id, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, id, "adapter.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ok := `{"id":"demo","name":{"ru":"Демо","en":"Demo"},"description":{"ru":"д","en":"d"},"version":"1.0.0","protocol":1,` +
		`"image":"ghcr.io/getmikan/adapter-demo","min_panel":"0.4.3","homepage":"https://example.com"}`
	write("demo", ok)
	runOK(t, "list", "-adapters", dir, "-version", "1.0.0")

	for name, body := range map[string]string{
		"unknown field": strings.Replace(ok, `"protocol":1`, `"protocol":1,"extra":true`, 1),
		"foreign image": strings.Replace(ok, "ghcr.io/getmikan/adapter-demo", "docker.io/evil/demo", 1),
		"no en name":    strings.Replace(ok, `"en":"Demo"`, `"de":"Demo"`, 1),
		"bad version":   strings.Replace(ok, `"version":"1.0.0"`, `"version":"latest"`, 1),
		"http homepage": strings.Replace(ok, "https://example.com", "http://example.com", 1),
	} {
		write("demo", body)
		if err := run([]string{"list", "-adapters", dir, "-version", "1.0.0"}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	write("demo", ok)
	write("other", ok) // id "demo" in the directory "other"
	runFails(t, "but the directory is", "list", "-adapters", dir, "-version", "1.0.0")

	// Two adapters at different versions: one tag cannot version both.
	write("other", strings.ReplaceAll(strings.Replace(ok, `"version":"1.0.0"`, `"version":"1.0.1"`, 1), "demo", "other"))
	runFails(t, "version 1.0.1, but the release is 1.0.0", "list", "-adapters", dir)
	runFails(t, "version 1.0.1, but the release is 1.0.0", "list", "-adapters", dir, "-version", "1.0.0")
}
