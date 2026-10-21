// index builds and signs the adapter catalog (used by .github/workflows/release.yml).
//
//	index list
//	    checks every payments/*/adapter.json and tools/*/adapter.json and prints the
//	    adapters as a JSON array of {"id", "version", "dir", "image"}
//	index plan -previous previous/index.json -base v1.0.3 -out plan.json
//	    selects changed adapters and reuses signed digests for the others
//	MARKETPLACE_CATALOG_KEY="$(cat catalog.pem)" [MARKETPLACE_SIGNING_KEY="$(cat release.pem)"] index build \
//	    -digest yookassa=sha256:… -digest cryptobot=sha256:… -digest platega=sha256:… -digest rollypay=sha256:… \
//	    -digest cardlink=sha256:… -out dist
//	    writes dist/index.json and dist/index.json.sig2 (the catalog's key, in its context), and
//	    dist/index.json.sig (the release key, for panels before 0.5.1.1) when that key is given
//	index verify dist/index.json
//	    checks dist/index.json.sig2 with the catalog's public key (or -key), and
//	    dist/index.json.sig with the release key's (or -legacy-key) when it is there
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
	"path"
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

// listed is an adapter as list prints it for the CI's image matrix, and as the release plan
// names the ones to build.
type listed struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Dir     string `json:"dir"`
	Image   string `json:"image"`
}

func listedOf(m catalog.Manifest) listed {
	return listed{ID: m.ID, Version: m.Version, Dir: dir(m), Image: m.Image}
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
		l[i] = listedOf(m)
	}
	return json.NewEncoder(out).Encode(l)
}

// digests is the repeatable -digest id=sha256:… flag.
type digests map[string]string

type releasePlan struct {
	Build []listed          `json:"build"`
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
	pubB64 := fs.String("key", catalog.PublicKey, "the catalog's public key, raw Ed25519 in base64")
	legacyB64 := fs.String("legacy-key", catalog.LegacyKey, "the release key that signed catalogs before index.json.sig2, raw Ed25519 in base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *previous == "" || *base == "" {
		return errors.New("-previous and -base are required")
	}
	// The previous catalog may be one from before the catalog's key: signed by the release
	// key alone.
	prev, err := readCatalog(*previous, *pubB64, *legacyB64)
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
	p, err := makeReleasePlan(*root, ms, prev, strings.Split(strings.TrimSuffix(string(paths), "\x00"), "\x00"))
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

func makeReleasePlan(root string, ms []catalog.Manifest, prev catalog.Index, paths []string) (releasePlan, error) {
	// A package whose image takes nothing from the build context but its own directory (the
	// telegram tool builds mikan's source at its tag) does not depend on the shared code.
	selfContained := map[string]bool{}
	for _, m := range ms {
		own, err := ownInputsOnly(root, dir(m))
		if err != nil {
			return releasePlan{}, err
		}
		selfContained[m.ID] = own
	}
	changed := map[string]bool{}
	shared := false
	for _, file := range paths {
		if file == "" {
			continue
		}
		parts := strings.Split(filepath.ToSlash(file), "/")
		switch {
		case strings.HasSuffix(file, ".md") || strings.HasSuffix(file, "_test.go"):
			// Documentation and tests are not inputs to the final adapter binary.
		case len(parts) > 1 && isPackage(parts[0]):
			changed[parts[1]] = true
		case file == "go.mod" || file == "go.sum" || strings.HasPrefix(file, "internal/adapter/"):
			shared = true
		case strings.HasPrefix(file, "internal/catalog/") || strings.HasPrefix(file, "internal/community/") || strings.HasPrefix(file, ".github/") || strings.HasPrefix(file, "cmd/index/") || strings.HasPrefix(file, "cmd/community/") || file == "LICENSE" || file == ".gitignore":
		default:
			shared = true // unknown image input: rebuild conservatively
		}
	}
	old := map[string]catalog.Entry{}
	for _, e := range prev.Adapters {
		old[e.ID] = e
	}
	p := releasePlan{Build: []listed{}, Reuse: map[string]string{}}
	for _, m := range ms {
		e, existed := old[m.ID]
		needsBuild := !existed || shared && !selfContained[m.ID] || changed[m.ID] || m.Version != e.Version
		if existed && m.Version != e.Version && compareVersion(m.Version, e.Version) <= 0 {
			return p, fmt.Errorf("adapter %s: version %s must be newer than %s", m.ID, m.Version, e.Version)
		}
		if existed && needsBuild && m.Version == e.Version {
			return p, fmt.Errorf("adapter %s changed but version is still %s; bump its version", m.ID, m.Version)
		}
		if needsBuild {
			p.Build = append(p.Build, listedOf(m))
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

// ownInputsOnly tells whether the package's Dockerfile copies from the build context (the
// repository root) only what lies in the package's own directory. COPY --from takes a stage
// and ADD of a URL takes no context, so neither counts.
func ownInputsOnly(root, pkg string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(root, pkg, "Dockerfile"))
	if err != nil {
		return false, err
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || !strings.EqualFold(fields[0], "COPY") && !strings.EqualFold(fields[0], "ADD") {
			continue
		}
		var args []string
		stage := false
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "--") {
				stage = stage || strings.HasPrefix(f, "--from=")
				continue
			}
			args = append(args, f)
		}
		if len(args) > 0 && strings.HasPrefix(args[0], "[") {
			return false, nil // the JSON form: not read here, so taken as shared
		}
		if stage || len(args) < 2 {
			continue
		}
		for _, src := range args[:len(args)-1] {
			if strings.Contains(src, "://") || strings.HasPrefix(src, "git@") {
				continue
			}
			if clean := path.Clean(src); clean != pkg && !strings.HasPrefix(clean, pkg+"/") {
				return false, nil
			}
		}
	}
	return true, nil
}

// isPackage tells a package directory, or adapters/, where the payment adapters were
// before the packages.
func isPackage(name string) bool {
	return name == "adapters" || slices.Contains(catalog.Categories, name)
}

// compareVersion compares the x.y.z[.w] and optional prerelease forms accepted by
// catalog.Manifest.Check, as the panel does: a missing fourth number is 0, and a release is
// newer than its prerelease.
func compareVersion(a, b string) int {
	coreA, preA, hasPreA := strings.Cut(a, "-")
	coreB, preB, hasPreB := strings.Cut(b, "-")
	partsA, partsB := strings.Split(coreA, "."), strings.Split(coreB, ".")
	for len(partsA) < 4 {
		partsA = append(partsA, "0")
	}
	for len(partsB) < 4 {
		partsB = append(partsB, "0")
	}
	for i := range 4 {
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

// reusePlanned checks plan.json against the manifests and adds the digests it reuses to ds:
// every adapter is either built (its digest is pushed, so given) or reused, never both, at
// the version and place the manifest says.
func reusePlanned(planFile string, ms []catalog.Manifest, ds digests) error {
	data, err := os.ReadFile(planFile)
	if err != nil {
		return err
	}
	var p releasePlan
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("plan: %w", err)
	}
	building := map[string]listed{}
	for _, b := range p.Build {
		if _, dup := building[b.ID]; dup {
			return fmt.Errorf("plan: duplicate adapter %s", b.ID)
		}
		building[b.ID] = b
	}
	for id, digest := range p.Reuse {
		if _, dup := building[id]; dup {
			return fmt.Errorf("plan: duplicate adapter %s", id)
		}
		if _, present := ds[id]; present {
			return fmt.Errorf("plan: unexpected pushed digest for reused adapter %s", id)
		}
		ds[id] = digest
	}
	for _, m := range ms {
		b, built := building[m.ID]
		if _, reused := p.Reuse[m.ID]; !built && !reused {
			return fmt.Errorf("plan: missing adapter %s", m.ID)
		}
		if built && b != listedOf(m) {
			return fmt.Errorf("plan: version or place mismatch for %s", m.ID)
		}
	}
	if len(building)+len(p.Reuse) != len(ms) {
		return errors.New("plan: unknown adapter")
	}
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
	key, err := catalog.PrivateKey(os.Getenv("MARKETPLACE_CATALOG_KEY"))
	if err != nil {
		return fmt.Errorf("MARKETPLACE_CATALOG_KEY: %w", err)
	}
	// The release key's signature is for the panels before 0.5.1.1, which read only that one:
	// made while the secret is still given.
	var legacy ed25519.PrivateKey
	if pemText := os.Getenv("MARKETPLACE_SIGNING_KEY"); pemText != "" {
		if legacy, err = catalog.PrivateKey(pemText); err != nil {
			return fmt.Errorf("MARKETPLACE_SIGNING_KEY: %w", err)
		}
	}
	ms, err := manifests(*root)
	if err != nil {
		return err
	}
	if *planFile != "" {
		if err := reusePlanned(*planFile, ms, ds); err != nil {
			return err
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
	sig := catalog.SignIn(catalog.Context, data, key)
	// The file must pass the checks the panel and the host make.
	if _, err := catalog.Open(data, sig, key.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	files := map[string][]byte{"index.json": data, "index.json" + catalog.SigSuffix: []byte(sig + "\n")}
	if legacy != nil {
		files["index.json.sig"] = []byte(catalog.Sign(data, legacy) + "\n")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(*outDir, name), content, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "index: %d adapters\n", len(idx.Adapters))
	return nil
}

// readCatalog reads index.json and its signature next to it (raw Ed25519 public keys in
// base64): index.json.sig2 by the catalog's key; with legacyB64 given and no .sig2 there,
// index.json.sig by the release key, as catalogs were signed before.
func readCatalog(file, pubB64, legacyB64 string) (catalog.Index, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return catalog.Index{}, err
	}
	sig, err := os.ReadFile(file + catalog.SigSuffix)
	if errors.Is(err, os.ErrNotExist) && legacyB64 != "" {
		return readLegacy(file, data, legacyB64)
	}
	if err != nil {
		return catalog.Index{}, err
	}
	pub, err := catalog.Key(pubB64)
	if err != nil {
		return catalog.Index{}, err
	}
	return catalog.Open(data, string(sig), pub)
}

// readLegacy checks index.json.sig, the release key's signature over data, the file's bytes.
func readLegacy(file string, data []byte, legacyB64 string) (catalog.Index, error) {
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		return catalog.Index{}, err
	}
	pub, err := catalog.Key(legacyB64)
	if err != nil {
		return catalog.Index{}, err
	}
	return catalog.Verify(data, string(sig), pub)
}

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubB64 := fs.String("key", catalog.PublicKey, "the catalog's public key, raw Ed25519 in base64")
	legacyB64 := fs.String("legacy-key", catalog.LegacyKey, "the release key, raw Ed25519 in base64, for index.json.sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: index verify [-key base64] [-legacy-key base64] dist/index.json")
	}
	idx, err := readCatalog(fs.Arg(0), *pubB64, "")
	if err != nil {
		return err
	}
	// The release key's signature, when it was made, must hold too: the panels before 0.5.1.1
	// read only that one.
	if data, err := os.ReadFile(fs.Arg(0)); err == nil {
		if _, err := os.Stat(fs.Arg(0) + ".sig"); err == nil {
			if _, err := readLegacy(fs.Arg(0), data, *legacyB64); err != nil {
				return fmt.Errorf("index.json.sig: %w", err)
			}
		}
	}
	for _, e := range idx.Adapters {
		fmt.Fprintf(out, "ok: %s %s %s %s@%s\n", e.Category, e.ID, e.Version, e.Image, e.Digest)
	}
	return nil
}
