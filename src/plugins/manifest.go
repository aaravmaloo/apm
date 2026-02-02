package plugins

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type Manifest struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	Description         string   `json:"description"`
	Author              string   `json:"author"`
	PermissionsRequired []string `json:"permissions_required"`
	AllowedFileTypes    []string `json:"allowed_file_types"`
	Commands            []string `json:"commands"`
	Hooks               []string `json:"hooks"`
}

func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	semverRegex := regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	if !semverRegex.MatchString(m.Version) {
		return fmt.Errorf("invalid version: %s (must follow semantic versioning)", m.Version)
	}

	allowedPermissions := map[string]bool{
		"vault.read":       true,
		"vault.write":      true,
		"file.storage":     true,
		"crypto.use":       true,
		"network.outbound": true,
	}

	for _, p := range m.PermissionsRequired {
		if !allowedPermissions[p] {
			return fmt.Errorf("unknown permission: %s", p)
		}
	}

	return nil
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return &m, nil
}
