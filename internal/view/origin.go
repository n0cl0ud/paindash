package view

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/n0cl0ud/paindash/internal/model"
)

var (
	repoNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	revisionRe = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

// Origin tells where to fix an image. It is first-party when its path is under
// one of owners (ghcr.io/<owner>/..., or <cache>/ghcr/<owner>/... through a
// pull-through cache): the path, not the label, decides, so that a third-party
// image never sends anyone to edit a repo. The source repo then comes from the
// OCI source label if it is one of ours, else is guessed from the image name.
// For a third-party image, the label names the upstream project.
func Origin(image, source, revision string, owners []string) model.ImageOrigin {
	var o model.ImageOrigin
	path := imagePath(image)
	owner, name := "", ""
	for _, ow := range owners {
		for i := 0; i < 2 && i+1 < len(path) && owner == ""; i++ {
			if strings.EqualFold(path[i], ow) {
				owner, name = ow, path[i+1]
			}
		}
	}
	o.FirstParty = owner != ""

	repoOwner, repoName := githubRepo(source)
	if repoOwner == "" {
		repoOwner = owner // "https://github.com//name": the owner got lost
	}
	ours := slices.ContainsFunc(owners, func(ow string) bool { return strings.EqualFold(ow, repoOwner) })
	if repoOwner != "" && repoName != "" && (ours || !o.FirstParty) {
		o.Repo = repoOwner + "/" + repoName
		if r := strings.ToLower(revision); revisionRe.MatchString(r) {
			o.Revision = r
		}
	} else if o.FirstParty {
		o.Repo, o.Guessed = owner+"/"+name, true
	}
	return o
}

// imagePath splits an image reference into its repository path, without the
// registry host, tag and digest: "ghcr.io/acme/x:1" -> [acme x].
func imagePath(image string) []string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	parts := strings.Split(image, "/")
	last := parts[len(parts)-1]
	if i := strings.Index(last, ":"); i >= 0 {
		parts[len(parts)-1] = last[:i]
	}
	if len(parts) > 1 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		parts = parts[1:]
	}
	return parts
}

// githubRepo extracts the owner and name of a GitHub repo URL. owner is ""
// when the URL lost it ("https://github.com//name"), both are "" when it is
// not a GitHub repo URL.
func githubRepo(source string) (owner, name string) {
	u, err := url.Parse(source)
	if err != nil || !strings.EqualFold(strings.TrimPrefix(u.Host, "www."), "github.com") {
		return "", ""
	}
	var segs []string
	for _, s := range strings.Split(u.Path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	switch {
	case len(segs) >= 2:
		owner, name = segs[0], segs[1]
	case len(segs) == 1 && strings.HasPrefix(u.Path, "//"):
		name = segs[0]
	default:
		return "", ""
	}
	name = strings.TrimSuffix(name, ".git")
	if !repoNameRe.MatchString(name) || owner != "" && !repoNameRe.MatchString(owner) {
		return "", ""
	}
	return owner, name
}
