package plugins

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest represents the structure of a plugin's manifest.json file
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

// Validate checks if the manifest contains valid data
func (m *Manifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("plugin name is required")
	}
	// Basic permission validation
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

// LoadManifest reads and parses a manifest.json file
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
