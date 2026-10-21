package community

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Repo is a GitHub repository as the indexer judges it.
type Repo struct {
	ID       int64    `json:"id"`
	FullName string   `json:"full_name"`
	Private  bool     `json:"private"`
	Archived bool     `json:"archived"`
	Template bool     `json:"is_template"`
	Topics   []string `json:"topics"`
	Stars    int      `json:"stargazers_count"`
}

// Listed: the repository may be in the registry at all.
func (r Repo) Listed() bool {
	return !r.Private && !r.Archived && !r.Template && !slices.Contains(r.Topics, NoIndex)
}

// Name is github.com/<owner>/<repo>, as a snapshot names it.
func (r Repo) Name() string { return "github.com/" + r.FullName }

// Read is what one repository gave in this run.
type Read struct {
	Repo *Repo // nil: the repository is gone (404)
	Doc  Doc
	Err  error // the release could not be read or used: nothing changes for it
	// Downloads are the pulls of the images of Doc, by image; an image missing from it could
	// not be counted this run and keeps the count it had.
	Downloads map[string]int
}

// RoundCount keeps two significant digits of a count of 100 or more: 12757 is 13000. A
// snapshot changes when the count does in a way a reader sees.
func RoundCount(n int) int {
	if n < 100 {
		return n
	}
	p := 1
	for n/p >= 100 {
		p *= 10
	}
	return (n + p/2) / p * p
}

// downloads is the count of e's image this run, or before when it could not be counted.
func (rd Read) downloads(e Entry, before int) int {
	if n, ok := rd.Downloads[e.Image]; ok {
		return RoundCount(n)
	}
	return before
}

// State is the registry as the indexer starts from it.
type State struct {
	Addons   []Addon   // the snapshots in the repository
	Revoked  []Revoked // revoked.json
	Official []string  // the catalog's ids
	OpenPRs  []string  // branches of the open pull requests
}

// Change is files to write (nil: delete), by path.
type Change map[string][]byte

// Review is a pull request for a person to look at: an addon new to the registry, or what
// cannot go in by itself (another key, another repository name, a wide permission).
type Review struct {
	Branch string
	Title  string
	Body   string
	Files  Change
}

// Plan is what a run does: one commit to main, and the pull requests.
type Plan struct {
	Commit  Change
	Notes   []string // what the commit does, one line each
	Reviews []Review
}

// Branch is the branch of the pull request of a repository: one at a time per repository.
func Branch(repoID int64) string { return fmt.Sprintf("community/repo-%d", repoID) }

// Encode is a snapshot as the registry keeps it.
func Encode(a Addon) []byte {
	data, _ := json.MarshalIndent(a, "", "  ")
	return append(data, '\n')
}

// MakePlan works out the run. known are the repositories the registry has snapshots of, read
// again; found are the ones the topic search turned up that it has none of, read for the first
// time. now is the run's time (unix).
func MakePlan(st State, known, found map[int64]Read, now int64) Plan {
	p := Plan{Commit: Change{}}
	open := map[string]bool{}
	for _, b := range st.OpenPRs {
		open[b] = true
	}
	byRepo := map[int64][]Addon{}
	taken := map[string]int64{} // id → the repository that holds it (0: the catalog's)
	for _, id := range append(slices.Clone(st.Official), Reserved...) {
		taken[id] = 0
	}
	for _, a := range st.Addons {
		byRepo[a.RepoID] = append(byRepo[a.RepoID], a)
		taken[a.ID] = a.RepoID
	}
	idx := Index{Revoked: st.Revoked}
	repoRevoked := func(r Repo) (Revoked, bool) { return idx.RevokedFor(Addon{Repo: r.Name()}) }

	for _, id := range sortedKeys(byRepo) {
		have := byRepo[id]
		rd, ok := known[id]
		if !ok {
			continue
		}
		if rd.Repo == nil || !rd.Repo.Listed() {
			// Gone, archived, made private or asked out: its addons leave the registry.
			for _, a := range have {
				p.Commit[a.Path()] = nil
				delete(taken, a.ID)
			}
			p.Notes = append(p.Notes, fmt.Sprintf("remove %s: the repository is gone or asked out", have[0].Repo))
			continue
		}
		if rd.Err != nil || open[Branch(id)] {
			// A release that cannot be read changes nothing; a pull request already waits.
			continue
		}
		r := *rd.Repo
		review := Review{Branch: Branch(id), Files: Change{}}
		var why []string
		whole := false
		if pin := have[0].Key; rd.Doc.Key != pin {
			why = append(why, keyChange(pin, rd.Doc.Key))
			whole = true
		}
		if r.Name() != have[0].Repo {
			why = append(why, fmt.Sprintf("the repository is now **%s** (was %s)", r.Name(), have[0].Repo))
			whole = true
		}
		entries := map[string]Entry{}
		for _, e := range rd.Doc.Entries {
			entries[e.ID] = e
		}
		for _, a := range have {
			e, listed := entries[a.ID]
			delete(entries, a.ID)
			if !listed {
				if whole {
					review.Files[a.Path()] = nil
				} else {
					p.Commit[a.Path()] = nil
					p.Notes = append(p.Notes, fmt.Sprintf("remove %s: no longer in %s", a.ID, a.Repo))
				}
				continue
			}
			next := advance(a, e, r, rd.Doc.Key, now)
			next.Downloads = rd.downloads(e, a.Downloads)
			wider := wide(e.Permissions, a.Permissions)
			if len(wider) > 0 {
				why = append(why, fmt.Sprintf("`%s` now asks for **%s**", a.ID, strings.Join(wider, ", ")))
			}
			if next.Path() != a.Path() {
				review.Files[a.Path()] = nil
			}
			switch {
			case whole || len(wider) > 0:
				review.Files[next.Path()] = Encode(next)
			case !slices.Equal(Encode(next), Encode(a)):
				p.Commit[next.Path()] = Encode(next)
				if next.Digest != a.Digest {
					p.Notes = append(p.Notes, fmt.Sprintf("update %s %s → %s", a.ID, a.Version, next.Version))
				}
			}
		}
		// What the repository lists besides is new to the registry: a person looks at it first.
		var fresh []Addon
		skipped := slices.Clone(rd.Doc.Skipped)
		for _, eid := range slices.Sorted(maps.Keys(entries)) {
			if holder, held := taken[eid]; held && holder != id {
				skipped = append(skipped, Skip{eid, "id_taken"})
				continue
			}
			if _, out := idx.RevokedFor(Addon{Entry: Entry{ID: eid}}); out {
				skipped = append(skipped, Skip{eid, "revoked"})
				continue
			}
			a := snapshot(entries[eid], r, rd.Doc.Key, now)
			a.Downloads = rd.downloads(a.Entry, 0)
			fresh = append(fresh, a)
			taken[eid] = id
			review.Files[a.Path()] = Encode(a)
		}
		if len(fresh) > 0 {
			why = append(why, fmt.Sprintf("%d new addon(s)", len(fresh)))
		}
		if len(review.Files) == 0 {
			continue
		}
		review.Title = fmt.Sprintf("community: review %s", r.FullName)
		review.Body = reviewBody(r, rd.Doc, why, skipped)
		p.Reviews = append(p.Reviews, review)
	}

	for _, id := range sortedKeys(found) {
		rd := found[id]
		if _, have := byRepo[id]; have || rd.Repo == nil || !rd.Repo.Listed() || rd.Err != nil || open[Branch(id)] {
			continue
		}
		r := *rd.Repo
		if _, out := repoRevoked(r); out {
			continue
		}
		review := Review{Branch: Branch(id), Files: Change{}}
		var fresh []Addon
		skipped := slices.Clone(rd.Doc.Skipped)
		for _, e := range rd.Doc.Entries {
			if _, held := taken[e.ID]; held {
				skipped = append(skipped, Skip{e.ID, "id_taken"})
				continue
			}
			if _, out := idx.RevokedFor(Addon{Entry: e}); out {
				skipped = append(skipped, Skip{e.ID, "revoked"})
				continue
			}
			a := snapshot(e, r, rd.Doc.Key, now)
			a.Downloads = rd.downloads(e, 0)
			fresh = append(fresh, a)
			taken[e.ID] = id
			review.Files[a.Path()] = Encode(a)
		}
		if len(fresh) == 0 {
			continue
		}
		review.Title = fmt.Sprintf("community: add %s", r.FullName)
		review.Body = reviewBody(r, rd.Doc, []string{"a repository new to the registry"}, skipped)
		p.Reviews = append(p.Reviews, review)
	}
	sort.Strings(p.Notes)
	return p
}

// snapshot is a new addon in the registry.
func snapshot(e Entry, r Repo, key string, now int64) Addon {
	return Addon{Entry: e, Repo: r.Name(), RepoID: r.ID, Key: key, Stars: r.Stars, AddedAt: now, UpdatedAt: now}
}

// advance is the snapshot after this run: the entry as the release has it now, the build it
// replaces kept as previous.
func advance(a Addon, e Entry, r Repo, key string, now int64) Addon {
	next := Addon{Entry: e, Repo: r.Name(), RepoID: r.ID, Key: key, Stars: r.Stars, Previous: a.Previous, AddedAt: a.AddedAt, UpdatedAt: a.UpdatedAt}
	if e.Digest != a.Digest {
		next.Previous = &Prior{Version: a.Version, Digest: a.Digest}
		next.UpdatedAt = now
	}
	return next
}

// wide is the wide permissions next asks for that before did not.
func wide(next, before []string) []string {
	var out []string
	for _, p := range Wide {
		if slices.Contains(next, p) && !slices.Contains(before, p) {
			out = append(out, p)
		}
	}
	return out
}

func keyChange(from, to string) string {
	switch {
	case from == "":
		return fmt.Sprintf("the release is now **signed** (key %s); it was not", Fingerprint(to))
	case to == "":
		return fmt.Sprintf("the release is **no longer signed** (was key %s)", Fingerprint(from))
	}
	return fmt.Sprintf("the release is signed with **another key**: %s (was %s)", Fingerprint(to), Fingerprint(from))
}

// reviewBody is what the reviewer reads: who, what it asks for, what it runs.
func reviewBody(r Repo, doc Doc, why []string, skipped []Skip) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Repository: https://%s (%d★)\n\n", r.Name(), r.Stars)
	if doc.Key != "" {
		fmt.Fprintf(&b, "Signed by key `%s`.\n\n", Fingerprint(doc.Key))
	} else {
		b.WriteString("**Not signed**: whoever controls the repository controls what panels are offered.\n\n")
	}
	b.WriteString("Why a review:\n")
	for _, w := range why {
		fmt.Fprintf(&b, "- %s\n", w)
	}
	b.WriteString("\n| id | kind | version | permissions | image |\n|---|---|---|---|---|\n")
	for _, e := range doc.Entries {
		perms := make([]string, len(e.Permissions))
		for i, p := range e.Permissions {
			perms[i] = p
			if slices.Contains(Wide, p) {
				perms[i] = "**" + p + "**"
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s/%s | %s | %s | `%s@%s` |\n", e.ID, e.Kind, e.Mode, e.Version, strings.Join(perms, ", "), e.Image, e.Digest)
	}
	if len(skipped) > 0 {
		b.WriteString("\nLeft out:\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "- `%s`: %s\n", s.ID, s.Reason)
		}
	}
	b.WriteString("\nBefore merging:\n- [ ] the repository is the author's own work, not a copy of someone else's addon\n" +
		"- [ ] the image is built from this repository (a workflow in it pushes it)\n" +
		"- [ ] the permissions fit what the addon says it does\n" +
		"\nmikan lists community addons and does not vouch for them: merging is not a review of the code.\n")
	return b.String()
}

func sortedKeys[V any](m map[int64]V) []int64 {
	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Fingerprint of an author's key as the panel shows it: the first 16 bytes of its SHA-256 in
// groups of four hex digits (addons.Fingerprint of mikan).
func Fingerprint(key string) string {
	pub, err := catalogKey(key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(pub)
	h := hex.EncodeToString(sum[:16])
	var groups []string
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, ":")
}

// ErrLayout is a snapshot that is not where its id and repository put it.
var ErrLayout = errors.New("community: snapshot out of place")
