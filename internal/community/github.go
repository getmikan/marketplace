package community

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// FileLimit bounds an author's release file; SigLimit its signature.
const (
	FileLimit = 1 << 20
	SigLimit  = 4096
)

// ErrNoRelease: the repository has no release, or none with a mikan addon file.
var ErrNoRelease = errors.New("community: no release with mikan-addon.json or index.json")

// GitHub is the REST API the indexer needs, with the workflow's token. API is the base
// (https://api.github.com; tests point it at a server of their own), Registry the registry's
// repository, owner/name. Web is the site (https://github.com): the count of pulls of a
// package is on its page, the API has none.
type GitHub struct {
	API      string
	Web      string
	Token    string
	Registry string
	Client   *http.Client
}

func NewGitHub(token, registry string) *GitHub {
	return &GitHub{API: "https://api.github.com", Web: "https://github.com", Token: token, Registry: registry, Client: &http.Client{Timeout: 30 * time.Second}}
}

// totalDownloads is the count on a package's page: "Total downloads" over the exact number
// in a title, whatever the page shows it rounded as.
var totalDownloads = regexp.MustCompile(`(?s)Total downloads</span>\s*<h3[^>]*title="(\d+)"`)

// Downloads is how many times image was pulled: a package of GitHub's container registry
// (ghcr.io/<owner>/<name>) of the owner of repository fullName, as the package's page under
// the repository counts it. 0 for an image elsewhere, a package the repository does not show,
// or a page that says nothing of it.
func (g *GitHub) Downloads(ctx context.Context, fullName, image string) (int, error) {
	path, ok := strings.CutPrefix(image, "ghcr.io/")
	if !ok {
		return 0, nil
	}
	owner, name, ok := strings.Cut(path, "/")
	repoOwner, _, _ := strings.Cut(fullName, "/")
	if !ok || !strings.EqualFold(owner, repoOwner) {
		return 0, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.Web+"/"+fullName+"/pkgs/container/"+url.PathEscape(name), nil)
	if err != nil {
		return 0, err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, &apiError{Status: resp.StatusCode}
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, err
	}
	m := totalDownloads.FindSubmatch(page)
	if m == nil {
		return 0, nil
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, nil
	}
	return n, nil
}

// apiError is an answer of the API that is not a success.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Body) }

func status(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// call makes one request; out (when not nil) takes the JSON answer.
func (g *GitHub) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	u := path
	if !strings.HasPrefix(path, "https://") && !strings.HasPrefix(path, "http://") {
		u = g.API + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "mikan-community-indexer")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{resp.StatusCode, strings.TrimSpace(string(data[:min(len(data), 300)]))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// Search is every public repository with the topic, forks included (a fork is found only by
// its topic, as on AllayHub).
func (g *GitHub) Search(ctx context.Context, topic string) ([]Repo, error) {
	var all []Repo
	for page := 1; page <= 10; page++ {
		var res struct {
			Items []Repo `json:"items"`
		}
		q := url.QueryEscape("topic:" + topic + " fork:true is:public")
		if err := g.call(ctx, http.MethodGet, fmt.Sprintf("/search/repositories?q=%s&per_page=100&page=%d", q, page), nil, &res); err != nil {
			return nil, err
		}
		all = append(all, res.Items...)
		if len(res.Items) < 100 {
			break
		}
	}
	return all, nil
}

// RepoByID is the repository wherever it is now; nil when it is gone.
func (g *GitHub) RepoByID(ctx context.Context, id int64) (*Repo, error) {
	var r Repo
	err := g.call(ctx, http.MethodGet, fmt.Sprintf("/repositories/%d", id), nil, &r)
	if s := status(err); s == http.StatusNotFound || s == http.StatusForbidden || s == http.StatusUnavailableForLegalReasons {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

type asset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// Release is the latest release's addon file (mikan-addon.json, else index.json) and its
// signature (nil without one).
func (g *GitHub) Release(ctx context.Context, fullName string) (file, sig []byte, err error) {
	var rel struct {
		Assets []asset `json:"assets"`
	}
	err = g.call(ctx, http.MethodGet, "/repos/"+fullName+"/releases/latest", nil, &rel)
	if status(err) == http.StatusNotFound {
		return nil, nil, ErrNoRelease
	}
	if err != nil {
		return nil, nil, err
	}
	find := func(name string) *asset {
		for i, a := range rel.Assets {
			if a.Name == name {
				return &rel.Assets[i]
			}
		}
		return nil
	}
	for _, name := range []string{"mikan-addon.json", "index.json"} {
		f := find(name)
		if f == nil {
			continue
		}
		if file, err = g.download(ctx, fullName, *f, FileLimit); err != nil {
			return nil, nil, err
		}
		if s := find(name + ".sig"); s != nil {
			if sig, err = g.download(ctx, fullName, *s, SigLimit); err != nil {
				return nil, nil, err
			}
		}
		return file, sig, nil
	}
	return nil, nil, ErrNoRelease
}

// download reads a release asset through the API, at most limit bytes.
func (g *GitHub) download(ctx context.Context, fullName string, a asset, limit int64) ([]byte, error) {
	if a.Size > limit {
		return nil, fmt.Errorf("community: %s of %s is larger than %d bytes", a.Name, fullName, limit)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/repos/%s/releases/assets/%d", g.API, fullName, a.ID), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "mikan-community-indexer")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &apiError{resp.StatusCode, a.Name}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("community: %s of %s is larger than %d bytes", a.Name, fullName, limit)
	}
	return data, nil
}

// OpenBranches is the head branches of the registry's open pull requests.
func (g *GitHub) OpenBranches(ctx context.Context) ([]string, error) {
	var out []string
	for page := 1; page <= 10; page++ {
		var prs []struct {
			Head struct {
				Ref string `json:"ref"`
			} `json:"head"`
		}
		if err := g.call(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls?state=open&per_page=100&page=%d", g.Registry, page), nil, &prs); err != nil {
			return nil, err
		}
		for _, pr := range prs {
			out = append(out, pr.Head.Ref)
		}
		if len(prs) < 100 {
			break
		}
	}
	return out, nil
}

// commit makes one commit of the files on top of parent and returns its sha.
func (g *GitHub) commit(ctx context.Context, parent, message string, files Change) (string, error) {
	var c struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := g.call(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/git/commits/%s", g.Registry, parent), nil, &c); err != nil {
		return "", err
	}
	// A file is its content; a deletion is a null sha. GitHub refuses an item with both.
	tree := []map[string]any{}
	for _, path := range sortedPaths(files) {
		it := map[string]any{"path": path, "mode": "100644", "type": "blob"}
		if data := files[path]; data != nil {
			it["content"] = string(data)
		} else {
			it["sha"] = nil
		}
		tree = append(tree, it)
	}
	var t struct {
		SHA string `json:"sha"`
	}
	if err := g.call(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/trees", g.Registry), map[string]any{"base_tree": c.Tree.SHA, "tree": tree}, &t); err != nil {
		return "", err
	}
	var nc struct {
		SHA string `json:"sha"`
	}
	if err := g.call(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/commits", g.Registry), map[string]any{"message": message, "tree": t.SHA, "parents": []string{parent}}, &nc); err != nil {
		return "", err
	}
	return nc.SHA, nil
}

// CommitMain puts one commit on main on top of base, the commit the run read the registry
// at. If main moved since, the update is refused (no force) and the next run does it again.
func (g *GitHub) CommitMain(ctx context.Context, base, message string, files Change) (string, error) {
	sha, err := g.commit(ctx, base, message, files)
	if err != nil {
		return "", err
	}
	return sha, g.call(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/git/refs/heads/main", g.Registry), map[string]any{"sha": sha, "force": false}, nil)
}

// OpenReview puts the files on the review's branch, cut from base, and opens its pull request.
// A branch left from a closed pull request is reset.
func (g *GitHub) OpenReview(ctx context.Context, base string, r Review) error {
	sha, err := g.commit(ctx, base, r.Title, r.Files)
	if err != nil {
		return err
	}
	err = g.call(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/git/refs", g.Registry), map[string]any{"ref": "refs/heads/" + r.Branch, "sha": sha}, nil)
	if status(err) == http.StatusUnprocessableEntity {
		err = g.call(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/git/refs/heads/%s", g.Registry, r.Branch), map[string]any{"sha": sha, "force": true}, nil)
	}
	if err != nil {
		return err
	}
	return g.call(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/pulls", g.Registry), map[string]any{"title": r.Title, "head": r.Branch, "base": "main", "body": r.Body}, nil)
}

func sortedPaths(c Change) []string {
	out := make([]string, 0, len(c))
	for p := range c {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}
