package community

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub answers what the indexer asks of the API and keeps what it was asked to do.
type fakeGitHub struct {
	mu    sync.Mutex
	calls []string
	trees []map[string]any
	refs  map[string]string
	prs   []map[string]any
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	if r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "no token", http.StatusUnauthorized)
		return
	}
	var in map[string]any
	if r.Body != nil {
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &in)
	}
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch p := r.URL.Path; {
	case p == "/search/repositories":
		if !strings.Contains(r.URL.Query().Get("q"), "topic:mikan-addon") {
			http.Error(w, "q", http.StatusBadRequest)
			return
		}
		reply(map[string]any{"items": []any{map[string]any{"id": 7, "full_name": "Author/hello", "topics": []string{"mikan-addon"}, "stargazers_count": 2}}})
	case p == "/repositories/7":
		reply(map[string]any{"id": 7, "full_name": "Author/hello"})
	case p == "/repositories/8":
		http.NotFound(w, r)
	case p == "/repos/Author/hello/releases/latest":
		reply(map[string]any{"assets": []any{map[string]any{"id": 1, "name": "mikan-addon.json", "size": 10}, map[string]any{"id": 2, "name": "other.zip"}}})
	case p == "/repos/Author/hello/releases/assets/1":
		if r.Header.Get("Accept") != "application/octet-stream" {
			http.Error(w, "accept", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"id":"hello"}`))
	case p == "/repos/None/x/releases/latest":
		http.NotFound(w, r)
	case p == "/repos/getmikan/reg/pulls" && r.Method == http.MethodGet:
		reply([]any{map[string]any{"head": map[string]any{"ref": "community/repo-9"}}})
	case strings.HasPrefix(p, "/repos/getmikan/reg/git/commits/"):
		reply(map[string]any{"tree": map[string]any{"sha": "tree0"}})
	case p == "/repos/getmikan/reg/git/trees":
		f.trees = append(f.trees, in)
		reply(map[string]any{"sha": "tree1"})
	case p == "/repos/getmikan/reg/git/commits":
		reply(map[string]any{"sha": "commit1"})
	case p == "/repos/getmikan/reg/git/refs":
		ref := in["ref"].(string)
		if _, ok := f.refs[ref]; ok {
			http.Error(w, "exists", http.StatusUnprocessableEntity)
			return
		}
		f.refs[ref] = in["sha"].(string)
	case strings.HasPrefix(p, "/repos/getmikan/reg/git/refs/heads/"):
		ref := "refs/heads/" + strings.TrimPrefix(p, "/repos/getmikan/reg/git/refs/heads/")
		if ref == "refs/heads/main" && in["force"] == true {
			http.Error(w, "main is never forced", http.StatusBadRequest)
			return
		}
		f.refs[ref] = in["sha"].(string)
	case p == "/repos/getmikan/reg/pulls" && r.Method == http.MethodPost:
		f.prs = append(f.prs, in)
	default:
		http.NotFound(w, r)
	}
}

func testGitHub(t *testing.T) (*GitHub, *fakeGitHub) {
	f := &fakeGitHub{refs: map[string]string{"refs/heads/community/repo-7": "old"}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	g := NewGitHub("tok", "getmikan/reg")
	g.API = srv.URL
	return g, f
}

func TestGitHubReads(t *testing.T) {
	g, _ := testGitHub(t)
	ctx := context.Background()
	repos, err := g.Search(ctx, Topic)
	if err != nil || len(repos) != 1 || repos[0].FullName != "Author/hello" || repos[0].Stars != 2 {
		t.Fatalf("search: %v %+v", err, repos)
	}
	if r, err := g.RepoByID(ctx, 8); err != nil || r != nil {
		t.Fatalf("a repository gone: %v %+v", err, r)
	}
	file, sig, err := g.Release(ctx, "Author/hello")
	if err != nil || string(file) != `{"id":"hello"}` || sig != nil {
		t.Fatalf("release: %v %q %q", err, file, sig)
	}
	if _, _, err := g.Release(ctx, "None/x"); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("no release: %v", err)
	}
	if b, err := g.OpenBranches(ctx); err != nil || len(b) != 1 || b[0] != "community/repo-9" {
		t.Fatalf("open: %v %v", err, b)
	}
}

func TestGitHubWrites(t *testing.T) {
	g, f := testGitHub(t)
	ctx := context.Background()
	sha, err := g.CommitMain(ctx, "base0", "chore: sync", Change{"addons/a/x.json": []byte("{}\n"), "addons/a/y.json": nil})
	if err != nil || sha != "commit1" || f.refs["refs/heads/main"] != "commit1" {
		t.Fatalf("commit: %v %v", err, f.refs)
	}
	tree := f.trees[0]["tree"].([]any)
	if f.trees[0]["base_tree"] != "tree0" || len(tree) != 2 {
		t.Fatalf("tree %+v", f.trees[0])
	}
	if del := tree[1].(map[string]any); del["path"] != "addons/a/y.json" || del["sha"] != nil || del["content"] != nil {
		t.Fatalf("a deletion is a null sha: %+v", del)
	}
	if _, hasSHA := tree[0].(map[string]any)["sha"]; hasSHA {
		t.Fatalf("a file carries its content and no sha: %+v", tree[0])
	}
	if _, isNull := tree[1].(map[string]any)["sha"]; !isNull {
		t.Fatal("a deletion names its sha as null")
	}
	// A branch left from a closed pull request is reset.
	if err := g.OpenReview(ctx, "base0", Review{Branch: "community/repo-7", Title: "community: add", Body: "b", Files: Change{"addons/a/x.json": []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	if f.refs["refs/heads/community/repo-7"] != "commit1" || len(f.prs) != 1 || f.prs[0]["head"] != "community/repo-7" || f.prs[0]["base"] != "main" {
		t.Fatalf("review: %v %+v", f.refs, f.prs)
	}
}

// The count of pulls comes off the package's page under the repository: the exact number of
// its title, for a ghcr.io image of the repository's owner only.
func TestGitHubDownloads(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Author/hello/pkgs/container/hello":
			_, _ = io.WriteString(w, `<div><span class="d-block color-fg-muted">Total downloads</span>
<h3 title="12757">12.8K</h3></div>`)
		case "/Author/hello/pkgs/container/blank":
			_, _ = io.WriteString(w, `<html>no counts here</html>`)
		case "/Author/hello/pkgs/container/broken":
			http.Error(w, "down", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(web.Close)
	g := NewGitHub("tok", "getmikan/reg")
	g.Web = web.URL
	ctx := context.Background()
	for image, want := range map[string]int{
		"ghcr.io/author/hello":   12757, // owners are told apart without case, as GitHub does
		"ghcr.io/author/blank":   0,
		"ghcr.io/author/missing": 0,
		"ghcr.io/other/hello":    0, // a package of someone else's is no count of this addon
		"docker.io/author/hello": 0,
	} {
		if n, err := g.Downloads(ctx, "Author/hello", image); err != nil || n != want {
			t.Errorf("%s: %d %v, want %d", image, n, err, want)
		}
	}
	if _, err := g.Downloads(ctx, "Author/hello", "ghcr.io/author/broken"); err == nil {
		t.Error("a page that fails is an error: the count stays as it was")
	}
}
