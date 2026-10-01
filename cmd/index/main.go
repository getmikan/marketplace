// index builds and signs the adapter catalog (used by .github/workflows/release.yml).
//
//	index list [-version 1.0.0]
//	    checks every adapters/*/adapter.json and that all are at this version (or at
//	    one version); prints their ids as a JSON array (the build matrix)
//	MARKETPLACE_SIGNING_KEY="$(cat key.pem)" index build -version 1.0.0 \
//	    -digest yookassa=sha256:… -digest cryptobot=sha256:… -digest platega=sha256:… -digest rollypay=sha256:… -out dist
//	    writes dist/index.json and dist/index.json.sig
//	index verify dist/index.json
//	    checks dist/index.json.sig with the release public key (or -key)
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/getmikan/marketplace/internal/catalog"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "index:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: index list|build|verify …")
	}
	switch args[0] {
	case "list":
		return list(args[1:], out)
	case "build":
		return build(args[1:], out)
	case "verify":
		return verify(args[1:], out)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// manifests reads dir/*/adapter.json; each must sit in a directory named after its id
// and carry the catalog version (one tag versions every adapter). With version "", they
// must all carry the same one.
func manifests(dir, version string) ([]catalog.Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "adapter.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no %s/*/adapter.json", dir)
	}
	var ms []catalog.Manifest
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		m, err := catalog.ParseManifest(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if name := filepath.Base(filepath.Dir(p)); m.ID != name {
			return nil, fmt.Errorf("%s: id %q, but the directory is %q", p, m.ID, name)
		}
		if version == "" {
			version = m.Version
		}
		if m.Version != version {
			return nil, fmt.Errorf("%s: version %s, but the release is %s", p, m.Version, version)
		}
		ms = append(ms, m)
	}
	return ms, nil
}

func list(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	version := fs.String("version", "", "catalog version, e.g. 1.0.0 (the tag without v); empty: any one version")
	dir := fs.String("adapters", "adapters", "where the adapters are")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ms, err := manifests(*dir, *version)
	if err != nil {
		return err
	}
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.ID
	}
	return json.NewEncoder(out).Encode(ids)
}

// digests is the repeatable -digest id=sha256:… flag.
type digests map[string]string

func (d digests) String() string { return fmt.Sprint(map[string]string(d)) }

func (d digests) Set(v string) error {
	id, digest, ok := strings.Cut(v, "=")
	if !ok || id == "" {
		return fmt.Errorf("%q: want id=sha256:…", v)
	}
	if _, dup := d[id]; dup {
		return fmt.Errorf("two digests for %s", id)
	}
	d[id] = digest
	return nil
}

func build(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	version := fs.String("version", "", "catalog version, e.g. 1.0.0 (the tag without v)")
	dir := fs.String("adapters", "adapters", "where the adapters are")
	outDir := fs.String("out", "dist", "output directory")
	ds := digests{}
	fs.Var(ds, "digest", "id=sha256:… of a pushed adapter image (one per adapter)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" {
		return errors.New("-version is required")
	}
	key, err := catalog.PrivateKey(os.Getenv("MARKETPLACE_SIGNING_KEY"))
	if err != nil {
		return fmt.Errorf("MARKETPLACE_SIGNING_KEY: %w", err)
	}
	ms, err := manifests(*dir, *version)
	if err != nil {
		return err
	}
	idx, err := catalog.Build(ms, ds, time.Now())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	sig := catalog.Sign(data, key)
	// The file must pass the checks the panel and the host make.
	if _, err := catalog.Verify(data, sig, key.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "index.json"), data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "index.json.sig"), []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "index %s: %d adapters\n", *version, len(idx.Adapters))
	return nil
}

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubB64 := fs.String("key", catalog.PublicKey, "public key, raw Ed25519 in base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: index verify [-key base64] dist/index.json")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(fs.Arg(0) + ".sig")
	if err != nil {
		return err
	}
	pub, err := catalog.Key(*pubB64)
	if err != nil {
		return err
	}
	idx, err := catalog.Verify(data, string(sig), pub)
	if err != nil {
		return err
	}
	for _, e := range idx.Adapters {
		fmt.Fprintf(out, "ok: %s %s %s@%s\n", e.ID, e.Version, e.Image, e.Digest)
	}
	return nil
}
