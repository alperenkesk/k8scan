package lint

import (
	"fmt"
	"os/exec"
)

// LoadKustomize runs `kubectl kustomize <kustomizePath>` and returns the parsed
// manifests as a ManifestStore.
// Requires kubectl v1.14+ (kustomize built-in) or the standalone kustomize binary.
func LoadKustomize(kustomizePath string) (*ManifestStore, error) {
	out, err := exec.Command("kubectl", "kustomize", kustomizePath).Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Errorf("kubectl kustomize failed: %w\n%s", err, stderr)
	}
	store := &ManifestStore{SourceMap: make(map[string]sourceRef)}
	store.parseYAML(out, kustomizePath)
	return store, nil
}
