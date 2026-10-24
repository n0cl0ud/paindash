package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PrepareDockerConfig writes the config.json syft uses to pull images: the
// shared cluster pull secret (a .dockerconfigjson, e.g. ghcr.io credentials)
// plus the ECR credential helper for the given registries, so ECR access uses
// the pod's IAM role. It returns the directory to use as DOCKER_CONFIG.
func PrepareDockerConfig(pullSecret string, ecrRegistries []string, dir string) (string, error) {
	cfg := map[string]any{}
	if pullSecret != "" {
		data, err := os.ReadFile(pullSecret)
		if err != nil {
			return "", fmt.Errorf("pull secret: %w", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return "", fmt.Errorf("pull secret %s: %w", pullSecret, err)
		}
	}
	if len(ecrRegistries) > 0 {
		helpers, _ := cfg["credHelpers"].(map[string]any)
		if helpers == nil {
			helpers = map[string]any{}
		}
		for _, r := range ecrRegistries {
			helpers[r] = "ecr-login"
		}
		cfg["credHelpers"] = helpers
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600)
}
