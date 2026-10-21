package community

import (
	"encoding/json"
	"strings"
	"testing"
)

func repo(id int64, name string) *Repo {
	return &Repo{ID: id, FullName: name, Topics: []string{Topic}, Stars: 1}
}

func doc(key string, entries ...Entry) Doc { return Doc{Key: key, Entries: entries} }

func decode(t *testing.T, data []byte) Addon {
	t.Helper()
	var a Addon
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPlanNewRepository(t *testing.T) {
	e := addon("hello", "", 0, "a").Entry
	taken := addon("yookassa", "", 0, "b").Entry
	p := MakePlan(State{Official: []string{"yookassa"}}, nil, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", e, taken)}}, 500)
	if len(p.Commit) != 0 || len(p.Reviews) != 1 {
		t.Fatalf("a new repository is a review only: %+v", p)
	}
	r := p.Reviews[0]
	if r.Branch != "community/repo-7" || len(r.Files) != 1 || !strings.Contains(r.Body, "`yookassa`: id_taken") || !strings.Contains(r.Body, "Not signed") {
		t.Fatalf("review %+v", r)
	}
	a := decode(t, r.Files["addons/author/hello.json"])
	if a.Repo != "github.com/Author/hello" || a.RepoID != 7 || a.AddedAt != 500 || a.Stars != 1 {
		t.Fatalf("snapshot %+v", a)
	}
}

func TestPlanSkipsNewRepositories(t *testing.T) {
	e := addon("hello", "", 0, "a").Entry
	archived := repo(1, "A/a")
	archived.Archived = true
	optOut := repo(2, "B/b")
	optOut.Topics = append(optOut.Topics, NoIndex)
	found := map[int64]Read{
		1: {Repo: archived, Doc: doc("", e)},
		2: {Repo: optOut, Doc: doc("", e)},
		3: {Repo: repo(3, "C/c"), Doc: doc("", e)},
		4: {Repo: repo(4, "D/d"), Doc: doc("", e)},
		5: {Repo: repo(5, "E/e"), Err: ErrNoRelease},
	}
	st := State{OpenPRs: []string{Branch(3)}, Revoked: []Revoked{{Repo: "github.com/d/D", Reason: "x", At: "2026-10-14"}}}
	if p := MakePlan(st, nil, found, 1); len(p.Reviews) != 0 || len(p.Commit) != 0 {
		t.Fatalf("archived, noindex, a pull request open, revoked, no release: %+v", p.Reviews)
	}
}

func TestPlanSameIDTwoNewRepositories(t *testing.T) {
	e := addon("hello", "", 0, "a").Entry
	p := MakePlan(State{}, nil, map[int64]Read{1: {Repo: repo(1, "A/a"), Doc: doc("", e)}, 2: {Repo: repo(2, "B/b"), Doc: doc("", e)}}, 1)
	if len(p.Reviews) != 1 || p.Reviews[0].Branch != Branch(1) {
		t.Fatalf("the first repository asks for the id: %+v", p.Reviews)
	}
}

func TestPlanUpdate(t *testing.T) {
	have := addon("hello", "github.com/Author/hello", 7, "a")
	next := have.Entry
	next.Digest, next.Version = digest("b"), "1.1.0"
	p := MakePlan(State{Addons: []Addon{have}}, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", next)}}, nil, 900)
	if len(p.Reviews) != 0 || len(p.Commit) != 1 {
		t.Fatalf("a new build goes in by itself: %+v", p)
	}
	a := decode(t, p.Commit[have.Path()])
	if a.Digest != digest("b") || a.Previous == nil || a.Previous.Digest != digest("a") || a.Previous.Version != "1.0.0" || a.UpdatedAt != 900 || a.AddedAt != 100 {
		t.Fatalf("snapshot %+v", a)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "update hello 1.0.0 → 1.1.0") {
		t.Fatalf("notes %v", p.Notes)
	}
	// Nothing changed: no commit.
	if p := MakePlan(State{Addons: []Addon{have}}, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", have.Entry)}}, nil, 900); len(p.Commit) != 0 {
		t.Fatalf("no change: %+v", p.Commit)
	}
}

func TestPlanReviews(t *testing.T) {
	_, key := newKey(t)
	have := addon("hello", "github.com/Author/hello", 7, "a")
	other := addon("other", "github.com/Author/hello", 7, "c")
	next := have.Entry
	next.Digest = digest("b")
	st := State{Addons: []Addon{have, other}}

	// Another key: everything of the repository waits for a person.
	p := MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc(key, next, other.Entry)}}, nil, 900)
	if len(p.Commit) != 0 || len(p.Reviews) != 1 || len(p.Reviews[0].Files) != 2 || !strings.Contains(p.Reviews[0].Body, "now **signed**") {
		t.Fatalf("key change: %+v", p)
	}

	// Another name: the snapshots move, by review.
	p = MakePlan(st, map[int64]Read{7: {Repo: repo(7, "NewOwner/hello"), Doc: doc("", next, other.Entry)}}, nil, 900)
	r := p.Reviews[0]
	if len(p.Commit) != 0 || r.Files["addons/author/hello.json"] != nil || r.Files["addons/newowner/hello.json"] == nil {
		t.Fatalf("rename: %+v", p)
	}
	if _, del := r.Files["addons/author/hello.json"]; !del {
		t.Fatal("the old snapshot goes")
	}

	// A wide permission: that addon waits, the other goes in.
	wider := next
	wider.Permissions = []string{"kv", "users:all"}
	otherNext := other.Entry
	otherNext.Digest = digest("d")
	p = MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", wider, otherNext)}}, nil, 900)
	if len(p.Commit) != 1 || p.Commit[other.Path()] == nil || len(p.Reviews) != 1 || p.Reviews[0].Files[have.Path()] == nil || !strings.Contains(p.Reviews[0].Body, "**users:all**") {
		t.Fatalf("wide: %+v", p)
	}

	// A new addon in a known repository: a review beside the commit.
	fresh := addon("fresh", "", 0, "e").Entry
	p = MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", next, other.Entry, fresh)}}, nil, 900)
	if len(p.Commit) != 1 || len(p.Reviews) != 1 || p.Reviews[0].Files["addons/author/fresh.json"] == nil {
		t.Fatalf("new in known: %+v", p)
	}

	// A pull request open for the repository: nothing until it is merged or closed.
	st.OpenPRs = []string{Branch(7)}
	if p := MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc(key, next)}}, nil, 900); len(p.Commit) != 0 || len(p.Reviews) != 0 {
		t.Fatalf("open: %+v", p)
	}
}

func TestPlanRemovals(t *testing.T) {
	have := addon("hello", "github.com/Author/hello", 7, "a")
	other := addon("other", "github.com/Author/hello", 7, "c")
	st := State{Addons: []Addon{have, other}}
	for name, rd := range map[string]Read{"gone": {}, "archived": {Repo: &Repo{ID: 7, FullName: "Author/hello", Archived: true}}} {
		p := MakePlan(st, map[int64]Read{7: rd}, nil, 1)
		if _, del := p.Commit[have.Path()]; !del || len(p.Commit) != 2 || len(p.Reviews) != 0 {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	// An addon the release no longer lists leaves by itself.
	p := MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", have.Entry)}}, nil, 1)
	if data, del := p.Commit[other.Path()]; !del || data != nil || len(p.Commit) != 1 {
		t.Fatalf("unlisted: %+v", p.Commit)
	}
	// A release that cannot be read changes nothing.
	if p := MakePlan(st, map[int64]Read{7: {Repo: repo(7, "Author/hello"), Err: ErrNoRelease}}, nil, 1); len(p.Commit) != 0 {
		t.Fatalf("unreadable: %+v", p.Commit)
	}
}

// A count of pulls goes in with two significant digits: a change a reader would see is a
// commit, one inside the rounding is none, and a run that could not count keeps the count.
func TestPlanDownloads(t *testing.T) {
	have := addon("hello", "github.com/Author/hello", 7, "a")
	read := func(n map[string]int) map[int64]Read {
		return map[int64]Read{7: {Repo: repo(7, "Author/hello"), Doc: doc("", have.Entry), Downloads: n}}
	}
	p := MakePlan(State{Addons: []Addon{have}}, read(map[string]int{have.Image: 12757}), nil, 900)
	if len(p.Commit) != 1 || decode(t, p.Commit[have.Path()]).Downloads != 13000 {
		t.Fatalf("the count goes in rounded: %+v", p.Commit)
	}
	have.Downloads = 13000
	if p := MakePlan(State{Addons: []Addon{have}}, read(map[string]int{have.Image: 12801}), nil, 900); len(p.Commit) != 0 {
		t.Fatalf("a change inside the rounding: %+v", p.Commit)
	}
	if p := MakePlan(State{Addons: []Addon{have}}, read(map[string]int{}), nil, 900); len(p.Commit) != 0 {
		t.Fatalf("a run that could not count keeps the count: %+v", p.Commit)
	}
	p = MakePlan(State{}, nil, map[int64]Read{8: {Repo: repo(8, "Author/new"), Doc: doc("", addon("fresh", "", 0, "b").Entry), Downloads: map[string]int{have.Image: 42}}}, 900)
	if len(p.Reviews) != 1 || decode(t, p.Reviews[0].Files["addons/author/fresh.json"]).Downloads != 42 {
		t.Fatalf("a new addon comes with its count: %+v", p.Reviews)
	}
	for n, want := range map[int]int{0: 0, 99: 99, 100: 100, 1234: 1200, 1250: 1300, 12757: 13000, 999_999: 1_000_000} {
		if got := RoundCount(n); got != want {
			t.Errorf("RoundCount(%d) = %d, want %d", n, got, want)
		}
	}
}
