package plugins

import (
	"encoding/json"
	"fmt"
	"os"
)

type FileStorageConfig struct {
	Enabled      bool     `json:"enabled"`
	AllowedTypes []string `json:"allowed_types"`
}

type CommandStep struct {
	Action   string `json:"action"`
	Key      string `json:"key,omitempty"`
	AssignTo string `json:"assign_to,omitempty"`
	Message  string `json:"message,omitempty"`

	Allowed []string `json:"allowed,omitempty"`
}

type CommandFlag struct {
	Type    string `json:"type"`
	Default string `json:"default"`
}

type CommandDef struct {
	Description string                 `json:"description"`
	Flags       map[string]CommandFlag `json:"flags"`
	Steps       []CommandStep          `json:"steps"`
}

type HookAction CommandStep

type PluginDef struct {
	SchemaVersion string                  `json:"schema_version"`
	Name          string                  `json:"name"`
	Version       string                  `json:"version"`
	Description   string                  `json:"description"`
	Author        string                  `json:"author"`
	Permissions   []string                `json:"permissions"`
	FileStorage   FileStorageConfig       `json:"file_storage"`
	Commands      map[string]CommandDef   `json:"commands"`
	Hooks         map[string][]HookAction `json:"hooks"`
}

func (p *PluginDef) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("plugin name required")
	}
	return nil
}

func LoadPluginDef(path string) (*PluginDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var def PluginDef
	if err := json.Unmarshal(data, &def); err != nil {
		return nil, err
	}
	return &def, def.Validate()
}
