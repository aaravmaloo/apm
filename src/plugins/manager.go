package plugins

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Plugin struct {
	Definition *PluginDef
	Path       string
}

type PluginManager struct {
	PluginsDir string
	Loaded     map[string]*Plugin
}

func NewPluginManager(rootDir string) *PluginManager {
	return &PluginManager{
		PluginsDir: filepath.Join(rootDir, "plugins_cache"),
		Loaded:     make(map[string]*Plugin),
	}
}

func (pm *PluginManager) LoadPlugins() error {
	if _, err := os.Stat(pm.PluginsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(pm.PluginsDir, 0755); err != nil {
			return err
		}
		return nil
	}

	entries, err := os.ReadDir(pm.PluginsDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pluginPath := filepath.Join(pm.PluginsDir, entry.Name())
		pluginDefPath := filepath.Join(pluginPath, "plugin.json")

		def, err := LoadPluginDef(pluginDefPath)
		if err != nil {

			continue
		}

		pm.Loaded[def.Name] = &Plugin{
			Definition: def,
			Path:       pluginPath,
		}
	}
	return nil
}

func (pm *PluginManager) InstallPlugin(name string, sourcePath string) error {
	targetPath := filepath.Join(pm.PluginsDir, name)

	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		return fmt.Errorf("plugin %s is already installed", name)
	}

	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("plugin source %s not found", sourcePath)
	}

	if err := os.MkdirAll(targetPath, 0755); err != nil {
		return err
	}

	files := []string{"plugin.json", "README.md"}
	for _, f := range files {
		srcFile := filepath.Join(sourcePath, f)
		dstFile := filepath.Join(targetPath, f)
		if _, err := os.Stat(srcFile); os.IsNotExist(err) {
			continue
		}
		if err := copyFile(srcFile, dstFile); err != nil {
			os.RemoveAll(targetPath)
			return err
		}
	}

	if _, err := LoadPluginDef(filepath.Join(targetPath, "plugin.json")); err != nil {
		os.RemoveAll(targetPath)
		return fmt.Errorf("invalid plugin definition: %v", err)
	}

	return nil
}

func (pm *PluginManager) RemovePlugin(name string) error {
	targetPath := filepath.Join(pm.PluginsDir, name)
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin %s not installed", name)
	}
	return os.RemoveAll(targetPath)
}

func (pm *PluginManager) ListPlugins() []string {
	var names []string
	for name := range pm.Loaded {
		names = append(names, name)
	}
	return names
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
