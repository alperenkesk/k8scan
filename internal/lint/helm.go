package lint

import (
	"fmt"
	"os/exec"
)

// LoadHelm runs `helm template <releaseName> <chartPath>` with optional value files
// and returns the parsed manifests as a ManifestStore.
// Requires helm v3 to be installed in PATH.
func LoadHelm(chartPath string, valueFiles []string) (*ManifestStore, error) {
	args := []string{"template", "release", chartPath}
	for _, vf := range valueFiles {
		args = append(args, "-f", vf)
	}
	cmd := exec.Command("helm", args...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		return nil, fmt.Errorf("helm template failed: %w\n%s", err, stderr)
	}
	store := &ManifestStore{SourceMap: make(map[string]sourceRef)}
	store.parseYAML(out, chartPath)
	return store, nil
}
