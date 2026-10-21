// community keeps the registry of community addons, getmikan/marketplace-community (used by
// its workflow). The registry's README says what it is; internal/community how.
//
//	GITHUB_TOKEN=… community sync -root registry -registry getmikan/marketplace-community -base <sha> [-dry-run]
//	    reads again the repositories the registry has, finds new ones by the mikan-addon
//	    topic, commits what may go in by itself to main and opens a pull request for the rest
//	community check -root registry
//	    checks every snapshot and revoked.json
//	MARKETPLACE_COMMUNITY_KEY="$(cat community.pem)" [MARKETPLACE_SIGNING_KEY="$(cat release.pem)"] community build -root registry -out dist
//	    writes dist/index.json and dist/index.json.sig2 (the registry's key, in its context), and
//	    dist/index.json.sig (the release key, for panels before 0.5.1.1) when that key is given
//	community verify dist/index.json
//	    checks dist/index.json.sig2 with the registry's public key (or -key), and
//	    dist/index.json.sig with the release key's (or -legacy-key) when it is there
//	community same new/index.json old/index.json
//	    prints "same" when the two list the same addons and revocations, else "changed"
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/getmikan/marketplace/internal/catalog"
	"github.com/getmikan/marketplace/internal/community"
)

// CatalogURL is the official catalog, whose ids no community addon may take.
const CatalogURL = "https://github.com/getmikan/marketplace/releases/latest/download/index.json"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "community:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: community sync|check|build|verify|same …")
	}
	switch args[0] {
	case "sync":
		return syncCmd(ctx, args[1:], out)
	case "check":
		return check(ctx, args[1:], out)
	case "build":
		return build(ctx, args[1:], out)
	case "verify":
		return verify(args[1:], out)
	case "same":
		return same(args[1:], out)
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// officialIDs is the ids of the signed catalog, read from a file (and its signature next to it)
// or the URL: by the catalog's key (index.json.sig2), or, for a catalog from before that key,
// by the release key (index.json.sig).
func officialIDs(ctx context.Context, src string) ([]string, error) {
	read := func(name string, limit int64) ([]byte, error) {
		if strings.HasPrefix(src, "https://") {
			return fetch(ctx, name, limit)
		}
		return os.ReadFile(name)
	}
	data, err := read(src, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	var idx catalog.Index
	if sig, err := read(src+catalog.SigSuffix, 4096); err == nil {
		pub, err := catalog.Key(catalog.PublicKey)
		if err != nil {
			return nil, err
		}
		if idx, err = catalog.Open(data, string(sig), pub); err != nil {
			return nil, err
		}
	} else {
		sig, err := read(src+".sig", 4096)
		if err != nil {
			return nil, fmt.Errorf("catalog: %w", err)
		}
		pub, err := catalog.Key(catalog.LegacyKey)
		if err != nil {
			return nil, err
		}
		if idx, err = catalog.Verify(data, string(sig), pub); err != nil {
			return nil, err
		}
	}
	ids := make([]string, len(idx.Adapters))
	for i, e := range idx.Adapters {
		ids[i] = e.ID
	}
	return ids, nil
}

func fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// source is what the sync reads from GitHub; *community.GitHub is it, the tests have their own.
type source interface {
	Search(ctx context.Context, topic string) ([]community.Repo, error)
	RepoByID(ctx context.Context, id int64) (*community.Repo, error)
	Release(ctx context.Context, fullName string) (file, sig []byte, err error)
	Downloads(ctx context.Context, fullName, image string) (int, error)
	OpenBranches(ctx context.Context) ([]string, error)
	CommitMain(ctx context.Context, base, message string, files community.Change) (string, error)
	OpenReview(ctx context.Context, base string, r community.Review) error
}

func syncCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	root := fs.String("root", ".", "a checkout of the registry")
	registry := fs.String("registry", "getmikan/marketplace-community", "the registry's repository")
	base := fs.String("base", "", "the commit the checkout is at")
	cat := fs.String("catalog", CatalogURL, "the official catalog: its URL, or a file with its .sig")
	dry := fs.Bool("dry-run", false, "print what would be done, change nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *base == "" && !*dry {
		return errors.New("-base is required")
	}
	official, err := officialIDs(ctx, *cat)
	if err != nil {
		return err
	}
	return sync(ctx, community.NewGitHub(os.Getenv("GITHUB_TOKEN"), *registry), *root, *base, official, *dry, time.Now().Unix(), out)
}

func sync(ctx context.Context, gh source, root, base string, official []string, dry bool, now int64, out io.Writer) error {
	addons, revoked, err := community.Load(root)
	if err != nil {
		return err
	}
	open, err := gh.OpenBranches(ctx)
	if err != nil {
		return err
	}
	read := func(r *community.Repo, pin string) community.Read {
		rd := community.Read{Repo: r}
		if r == nil || !r.Listed() {
			return rd
		}
		file, sig, err := gh.Release(ctx, r.FullName)
		if err == nil {
			rd.Doc, err = community.ParseDoc(file, sig, pin)
		}
		if err != nil {
			rd.Err = err
			fmt.Fprintf(out, "skip %s: %v\n", r.FullName, err)
			return rd
		}
		// A count that cannot be had this run is left out: the snapshot keeps the one it had.
		rd.Downloads = map[string]int{}
		for _, e := range rd.Doc.Entries {
			if _, done := rd.Downloads[e.Image]; done {
				continue
			}
			n, err := gh.Downloads(ctx, r.FullName, e.Image)
			if err != nil {
				fmt.Fprintf(out, "downloads of %s: %v\n", e.Image, err)
				continue
			}
			rd.Downloads[e.Image] = n
		}
		return rd
	}
	known := map[int64]community.Read{}
	for _, a := range addons {
		if _, done := known[a.RepoID]; done {
			continue
		}
		r, err := gh.RepoByID(ctx, a.RepoID)
		if err != nil {
			// The API failing says nothing of the repository: it stays as it is.
			fmt.Fprintf(out, "skip %s: %v\n", a.Repo, err)
			known[a.RepoID] = community.Read{Repo: &community.Repo{ID: a.RepoID, FullName: strings.TrimPrefix(a.Repo, "github.com/")}, Err: err}
			continue
		}
		known[a.RepoID] = read(r, a.Key)
	}
	repos, err := gh.Search(ctx, community.Topic)
	if err != nil {
		return err
	}
	found := map[int64]community.Read{}
	for _, r := range repos {
		if _, have := known[r.ID]; have {
			continue
		}
		found[r.ID] = read(&r, "")
	}
	p := community.MakePlan(community.State{Addons: addons, Revoked: revoked, Official: official, OpenPRs: open}, known, found, now)
	for _, n := range p.Notes {
		fmt.Fprintln(out, n)
	}
	for _, r := range p.Reviews {
		fmt.Fprintf(out, "review %s: %s (%d files)\n", r.Branch, r.Title, len(r.Files))
	}
	if dry {
		for _, path := range sortedPaths(p.Commit) {
			fmt.Fprintf(out, "commit %s\n", path)
		}
		return nil
	}
	var errs []error
	if len(p.Commit) > 0 {
		msg := "chore: sync community index\n\n" + strings.Join(p.Notes, "\n")
		sha, err := gh.CommitMain(ctx, base, msg, p.Commit)
		if err != nil {
			errs = append(errs, fmt.Errorf("commit: %w", err))
		} else {
			fmt.Fprintf(out, "committed %s\n", sha)
		}
	}
	for _, r := range p.Reviews {
		// A review is cut from the commit the run read: the sync commit, if any, is not in it,
		// and touches other files.
		if err := gh.OpenReview(ctx, base, r); err != nil {
			errs = append(errs, fmt.Errorf("review %s: %w", r.Branch, err))
		}
	}
	return errors.Join(errs...)
}

func sortedPaths(c community.Change) []string {
	out := make([]string, 0, len(c))
	for p := range c {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func buildIndex(ctx context.Context, root, cat string) (community.Index, error) {
	addons, revoked, err := community.Load(root)
	if err != nil {
		return community.Index{}, err
	}
	official, err := officialIDs(ctx, cat)
	if err != nil {
		return community.Index{}, err
	}
	return community.Build(addons, revoked, official, time.Now())
}

func check(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	root := fs.String("root", ".", "a checkout of the registry")
	cat := fs.String("catalog", CatalogURL, "the official catalog: its URL, or a file with its .sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	idx, err := buildIndex(ctx, *root, *cat)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "ok: %d addons, %d revoked\n", len(idx.Addons), len(idx.Revoked))
	return nil
}

func build(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	root := fs.String("root", ".", "a checkout of the registry")
	outDir := fs.String("out", "dist", "output directory")
	cat := fs.String("catalog", CatalogURL, "the official catalog: its URL, or a file with its .sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := catalog.PrivateKey(os.Getenv("MARKETPLACE_COMMUNITY_KEY"))
	if err != nil {
		return fmt.Errorf("MARKETPLACE_COMMUNITY_KEY: %w", err)
	}
	// The release key's signature is for the panels before 0.5.1.1, which read only that one:
	// made while the secret is still given.
	var legacy ed25519.PrivateKey
	if pemText := os.Getenv("MARKETPLACE_SIGNING_KEY"); pemText != "" {
		if legacy, err = catalog.PrivateKey(pemText); err != nil {
			return fmt.Errorf("MARKETPLACE_SIGNING_KEY: %w", err)
		}
	}
	idx, err := buildIndex(ctx, *root, *cat)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	sig := community.SignIn(data, key)
	// The file must pass the checks a panel makes.
	if _, err := community.Open(data, sig, key.Public().(ed25519.PublicKey), nil); err != nil {
		return err
	}
	files := map[string][]byte{"index.json": data, "index.json" + catalog.SigSuffix: []byte(sig + "\n")}
	if legacy != nil {
		files["index.json.sig"] = []byte(community.Sign(data, legacy) + "\n")
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(*outDir, name), content, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "index: %d addons, %d revoked\n", len(idx.Addons), len(idx.Revoked))
	return nil
}

func verify(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubB64 := fs.String("key", community.PublicKey, "the registry's public key, raw Ed25519 in base64")
	legacyB64 := fs.String("legacy-key", catalog.LegacyKey, "the release key, raw Ed25519 in base64, for index.json.sig")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: community verify [-key base64] [-legacy-key base64] dist/index.json")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(fs.Arg(0) + catalog.SigSuffix)
	if err != nil {
		return err
	}
	pub, err := catalog.Key(*pubB64)
	if err != nil {
		return err
	}
	idx, err := community.Open(data, string(sig), pub, nil)
	if err != nil {
		return err
	}
	// The release key's signature, when it was made, must hold too: the panels before 0.5.1.1
	// read only that one.
	if legacySig, err := os.ReadFile(fs.Arg(0) + ".sig"); err == nil {
		legacy, err := catalog.Key(*legacyB64)
		if err != nil {
			return err
		}
		if _, err := community.Verify(data, string(legacySig), legacy, nil); err != nil {
			return fmt.Errorf("index.json.sig: %w", err)
		}
	}
	for _, a := range idx.Addons {
		fmt.Fprintf(out, "ok: %s %s %s %s@%s\n", a.ID, a.Version, a.Repo, a.Image, a.Digest)
	}
	for _, r := range idx.Revoked {
		fmt.Fprintf(out, "revoked: %s%s %s\n", r.ID, r.Repo, r.At)
	}
	return nil
}

func same(args []string, out io.Writer) error {
	if len(args) != 2 {
		return errors.New("usage: community same new/index.json old/index.json")
	}
	var idx [2]community.Index
	for i, f := range args {
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := json.NewDecoder(bytes.NewReader(data)).Decode(&idx[i]); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	if community.SameContent(idx[0], idx[1]) {
		fmt.Fprintln(out, "same")
	} else {
		fmt.Fprintln(out, "changed")
	}
	return nil
}
