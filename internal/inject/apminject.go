package inject

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrAPMInjectNotFound = errors.New(".apminject not found")

type InjectMapping struct {
	Entry string `yaml:"entry"`
	As    string `yaml:"as"`
}

func FindAPMInjectFile(startDir string) (string, error) {
	if startDir == "" {
		return "", fmt.Errorf("start directory is empty")
	}

	dir := startDir
	for {
		candidate := filepath.Join(dir, ".apminject")
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", ErrAPMInjectNotFound
}

func ParseAPMInjectFile(path string) ([]InjectMapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var mappings []InjectMapping
	if err := yaml.Unmarshal(data, &mappings); err == nil && len(mappings) > 0 {
		return sanitizeMappings(mappings), nil
	}

	var wrapped struct {
		Entries []InjectMapping `yaml:"entries"`
		Inject  []InjectMapping `yaml:"inject"`
	}
	if err := yaml.Unmarshal(data, &wrapped); err != nil {
		return nil, err
	}

	if len(wrapped.Entries) == 0 && len(wrapped.Inject) == 0 {
		return nil, fmt.Errorf("no inject entries found in %s", path)
	}

	if len(wrapped.Entries) > 0 {
		return sanitizeMappings(wrapped.Entries), nil
	}
	return sanitizeMappings(wrapped.Inject), nil
}

func sanitizeMappings(mappings []InjectMapping) []InjectMapping {
	out := make([]InjectMapping, 0, len(mappings))
	for _, m := range mappings {
		m.Entry = strings.TrimSpace(m.Entry)
		m.As = strings.TrimSpace(m.As)
		if m.Entry == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}
