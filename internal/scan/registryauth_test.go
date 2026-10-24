package scan

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareDockerConfig(t *testing.T) {
	tmp := t.TempDir()
	secret := filepath.Join(tmp, ".dockerconfigjson")
	auth := base64.StdEncoding.EncodeToString([]byte("user:token")) // fake credential gitleaks:allow
	if err := os.WriteFile(secret, []byte(`{"auths":{"ghcr.io":{"auth":"`+auth+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := PrepareDockerConfig(secret, []string{"123.dkr.ecr.us-east-1.amazonaws.com"}, filepath.Join(tmp, "docker"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Auths       map[string]any    `json:"auths"`
		CredHelpers map[string]string `json:"credHelpers"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Auths["ghcr.io"]; !ok {
		t.Errorf("ghcr.io auth lost: %s", data)
	}
	if got.CredHelpers["123.dkr.ecr.us-east-1.amazonaws.com"] != "ecr-login" {
		t.Errorf("ECR helper missing: %s", data)
	}
}
