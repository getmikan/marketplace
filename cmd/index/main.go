// index builds and signs the adapter catalog (used by .github/workflows/release.yml).
//
//	index list
//	    checks every payments/*/adapter.json and tools/*/adapter.json and prints the
//	    adapters as a JSON array of {"id", "dir", "image"}
//	index plan -previous previous/index.json -base v1.0.3 -out plan.json
//	    selects changed adapters and reuses signed digests for the others
//	MARKETPLACE_SIGNING_KEY="$(cat key.pem)" index build \
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
	"os/exec"
	"path/filepath"
	"slices"
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
		return errors.New("usage: index list|plan|build|verify …")
	}
	switch args[0] {
	case "list":
		return list(args[1:], out)
	case "build":
		return build(args[1:], out)
	case "plan":
		return plan(args[1:], out)
	case "verify":
		return verify(args[1:], out)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// manifests reads <category>/*/adapter.json under root for every package; each must sit
// in a directory named after its id, in the directory of its category.
func manifests(root string) ([]catalog.Manifest, error) {
	var ms []catalog.Manifest
	seen := map[string]string{}
	for _, category := range catalog.Categories {
		paths, err := filepath.Glob(filepath.Join(root, category, "*", "adapter.json"))
		if err != nil {
			return nil, err
		}
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
			if m.Category != category {
				return nil, fmt.Errorf("%s: category %q, but it is in %s/", p, m.Category, category)
			}
			if other, dup := seen[m.ID]; dup {
				return nil, fmt.Errorf("%s: id %q is taken in %s/", p, m.ID, other)
			}
			seen[m.ID] = category
			ms = append(ms, m)
		}
	}
	if len(ms) == 0 {
		return nil, fmt.Errorf("no adapters in %s", strings.Join(catalog.Categories, "/, ")+"/")
	}
	return ms, nil
}

// dir is where an adapter's code and Dockerfile are, from the repository root.
func dir(m catalog.Manifest) string { return m.Category + "/" + m.ID }

// listed is an adapter as list prints it, for the CI's image matrix.
type listed struct {
	ID    string `json:"id"`
	Dir   string `json:"dir"`
	Image string `json:"image"`
}

func list(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	root := fs.String("root", ".", "the repository root, where the packages are")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ms, err := manifests(*root)
	if err != nil {
		return err
	}
	l := make([]listed, len(ms))
	for i, m := range ms {
		l[i] = listed{ID: m.ID, Dir: dir(m), Image: m.Image}
	}
	return json.NewEncoder(out).Encode(l)
}

// digests is the repeatable -digest id=sha256:… flag.
type digests map[string]string

type buildAdapter struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Dir     string `json:"dir"`
	Image   string `json:"image"`
}

type releasePlan struct {
	Build []buildAdapter    `json:"build"`
	Reuse map[string]string `json:"reuse"`
}

// plan verifies the previous published catalog, then compares its Git tag with
// HEAD. All image inputs are covered; changed image code requires a new version.
func plan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	root := fs.String("root", ".", "the repository root, where the packages are")
	previous := fs.String("previous", "", "previous signed index.json")
	base := fs.String("base", "", "Git tag of the previous release")
	outFile := fs.String("out", "plan.json", "release plan output")
	pubB64 := fs.String("key", catalog.PublicKey, "public key, raw Ed25519 in base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *previous == "" || *base == "" {
		return errors.New("-previous and -base are required")
	}
	data, err := os.ReadFile(*previous)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*previous + ".sig")
	if err != nil {
		return err
	}
	pub, err := catalog.Key(*pubB64)
	if err != nil {
		return err
	}
	prev, err := catalog.Verify(data, string(sig), pub)
	if err != nil {
		return fmt.Errorf("previous catalog: %w", err)
	}
	ms, err := manifests(*root)
	if err != nil {
		return err
	}
	// A missing or unrelated base could silently reuse a stale image.
	if output, err := exec.Command("git", "merge-base", "--is-ancestor", *base, "HEAD").CombinedOutput(); err != nil {
		return fmt.Errorf("base %q is not an ancestor of HEAD: %s: %w", *base, strings.TrimSpace(string(output)), err)
	}
	paths, err := exec.Command("git", "diff", "--name-only", "-z", *base, "HEAD").Output()
	if err != nil {
		return fmt.Errorf("git diff from %q: %w", *base, err)
	}
	p, err := makeReleasePlan(ms, prev, strings.Split(strings.TrimSuffix(string(paths), "\x00"), "\x00"))
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outFile, encoded, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "%s\n", encoded)
	return err
}

func makeReleasePlan(ms []catalog.Manifest, prev catalog.Index, paths []string) (releasePlan, error) {
	changed := map[string]bool{}
	shared := false
	for _, path := range paths {
		if path == "" {
			continue
		}
		parts := strings.Split(filepath.ToSlash(path), "/")
		switch {
		case strings.HasSuffix(path, ".md") || strings.HasSuffix(path, "_test.go"):
			// Documentation and tests are not inputs to the final adapter binary.
		case len(parts) > 1 && isPackage(parts[0]):
			changed[parts[1]] = true
		case path == "go.mod" || path == "go.sum" || strings.HasPrefix(path, "internal/adapter/"):
			shared = true
		case strings.HasPrefix(path, "internal/catalog/") || strings.HasPrefix(path, ".github/") || strings.HasPrefix(path, "cmd/index/") || path == "LICENSE" || path == ".gitignore":
		default:
			shared = true // unknown image input: rebuild conservatively
		}
	}
	old := map[string]catalog.Entry{}
	for _, e := range prev.Adapters {
		old[e.ID] = e
	}
	p := releasePlan{Build: []buildAdapter{}, Reuse: map[string]string{}}
	for _, m := range ms {
		e, existed := old[m.ID]
		needsBuild := !existed || shared || changed[m.ID] || m.Version != e.Version
		if existed && m.Version != e.Version && compareVersion(m.Version, e.Version) <= 0 {
			return p, fmt.Errorf("adapter %s: version %s must be newer than %s", m.ID, m.Version, e.Version)
		}
		if existed && needsBuild && m.Version == e.Version {
			return p, fmt.Errorf("adapter %s changed but version is still %s; bump its version", m.ID, m.Version)
		}
		if needsBuild {
			p.Build = append(p.Build, buildAdapter{ID: m.ID, Version: m.Version, Dir: dir(m), Image: m.Image})
		} else {
			p.Reuse[m.ID] = e.Digest
		}
		delete(old, m.ID)
	}
	if len(old) != 0 {
		return p, fmt.Errorf("adapter removed from catalog; handle removal explicitly: %v", old)
	}
	return p, nil
}

// isPackage tells a package directory, or adapters/, where the payment adapters were
// before the packages.
func isPackage(name string) bool {
	return name == "adapters" || slices.Contains(catalog.Categories, name)
}

// compareVersion compares the x.y.z and optional prerelease forms accepted by
// catalog.Manifest.Check. A release is newer than its prerelease.
func compareVersion(a, b string) int {
	coreA, preA, hasPreA := strings.Cut(a, "-")
	coreB, preB, hasPreB := strings.Cut(b, "-")
	partsA, partsB := strings.Split(coreA, "."), strings.Split(coreB, ".")
	for i := range partsA {
		if c := compareNumeric(partsA[i], partsB[i]); c != 0 {
			return c
		}
	}
	if hasPreA != hasPreB {
		if hasPreA {
			return -1
		}
		return 1
	}
	if !hasPreA {
		return 0
	}
	aIDs, bIDs := strings.Split(preA, "."), strings.Split(preB, ".")
	for i := 0; i < len(aIDs) && i < len(bIDs); i++ {
		aN := allDigits(aIDs[i])
		bN := allDigits(bIDs[i])
		switch {
		case aN && bN:
			if c := compareNumeric(aIDs[i], bIDs[i]); c != 0 {
				return c
			}
		case aN:
			return -1
		case bN:
			return 1
		default:
			if c := strings.Compare(aIDs[i], bIDs[i]); c != 0 {
				return c
			}
		}
	}
	if len(aIDs) < len(bIDs) {
		return -1
	}
	if len(aIDs) > len(bIDs) {
		return 1
	}
	return 0
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

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
	root := fs.String("root", ".", "the repository root, where the packages are")
	outDir := fs.String("out", "dist", "output directory")
	planFile := fs.String("plan", "", "plan.json with verified digests to reuse")
	ds := digests{}
	fs.Var(ds, "digest", "id=sha256:… of a pushed adapter image (one per adapter)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := catalog.PrivateKey(os.Getenv("MARKETPLACE_SIGNING_KEY"))
	if err != nil {
		return fmt.Errorf("MARKETPLACE_SIGNING_KEY: %w", err)
	}
	ms, err := manifests(*root)
	if err != nil {
		return err
	}
	if *planFile != "" {
		data, err := os.ReadFile(*planFile)
		if err != nil {
			return err
		}
		var p releasePlan
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("plan: %w", err)
		}
		allowed := map[string]bool{}
		for _, b := range p.Build {
			if allowed[b.ID] {
				return fmt.Errorf("plan: duplicate adapter %s", b.ID)
			}
			allowed[b.ID] = true
		}
		for id, digest := range p.Reuse {
			if allowed[id] {
				return fmt.Errorf("plan: duplicate adapter %s", id)
			}
			allowed[id] = true
			if _, present := ds[id]; present {
				return fmt.Errorf("plan: unexpected pushed digest for reused adapter %s", id)
			}
			ds[id] = digest
		}
		for _, m := range ms {
			if !allowed[m.ID] {
				return fmt.Errorf("plan: missing adapter %s", m.ID)
			}
			for _, b := range p.Build {
				if b.ID == m.ID && (b.Version != m.Version || b.Dir != dir(m) || b.Image != m.Image) {
					return fmt.Errorf("plan: version or place mismatch for %s", m.ID)
				}
			}
		}
		if len(allowed) != len(ms) {
			return errors.New("plan: unknown adapter")
		}
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
	fmt.Fprintf(out, "index: %d adapters\n", len(idx.Adapters))
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
		fmt.Fprintf(out, "ok: %s %s %s %s@%s\n", e.Category, e.ID, e.Version, e.Image, e.Digest)
	}
	return nil
}
