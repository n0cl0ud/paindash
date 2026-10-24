package view

import (
	"testing"

	"github.com/n0cl0ud/paindash/internal/model"
)

func TestOrigin(t *testing.T) {
	const ecr = "123456789012.dkr.ecr.us-east-1.amazonaws.com/"
	owners := []string{"acme"}
	for _, tc := range []struct {
		image, source, revision string
		want                    model.ImageOrigin
	}{
		{"ghcr.io/acme/paindash:7f0c839@sha256:fffe", "https://github.com/acme/paindash", "7F0C8394",
			model.ImageOrigin{FirstParty: true, Repo: "acme/paindash", Revision: "7f0c8394"}},
		// Through the ECR pull-through cache, monorepo image, ".git" suffix.
		{ecr + "ghcr/acme/store-backend:v1.2.0", "https://github.com/acme/store.git", "",
			model.ImageOrigin{FirstParty: true, Repo: "acme/store"}},
		// Label that lost its owner.
		{"ghcr.io/acme/www-acme-example-backend:v1", "https://github.com//www.acme.example", "abc1234",
			model.ImageOrigin{FirstParty: true, Repo: "acme/www.acme.example", Revision: "abc1234"}},
		// No label, or one pointing outside our owners: guessed from the image.
		{"ghcr.io/acme/tools/build-agent:1.0", "", "abc1234",
			model.ImageOrigin{FirstParty: true, Repo: "acme/tools", Guessed: true}},
		{"ghcr.io/acme/forked-tool:v1.0.0", "https://github.com/upstream/forked-tool", "",
			model.ImageOrigin{FirstParty: true, Repo: "acme/forked-tool", Guessed: true}},
		// Third-party: the label is the upstream project, never ours to edit.
		{ecr + "ghcr/upstream/controller:v1.0.0", "https://github.com/upstream/controller", "0123456789abcdef0123456789abcdef01234567",
			model.ImageOrigin{Repo: "upstream/controller", Revision: "0123456789abcdef0123456789abcdef01234567"}},
		{"quay.io/prometheus/prometheus:v3.0.0", "", "", model.ImageOrigin{}},
		{"nginx:1.27", "https://gitlab.com/x/y", "", model.ImageOrigin{}},
		{"docker.io/library/redis:7", "https://github.com/docker-library", "", model.ImageOrigin{}},
		{"registry.example:5000/acme/x:1", "javascript:alert(1)", "", model.ImageOrigin{FirstParty: true, Repo: "acme/x", Guessed: true}},
	} {
		if got := Origin(tc.image, tc.source, tc.revision, owners); got != tc.want {
			t.Errorf("%s (%s): got %+v, want %+v", tc.image, tc.source, got, tc.want)
		}
	}
}
