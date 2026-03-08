package tui

import (
	"context"
	"fmt"
	src "github.com/aaravmaloo/apm/src"
	"github.com/aaravmaloo/apm/src/plugins"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PluginCommandSpec struct {
	Name        string
	Description string
	Flags       map[string]plugins.CommandFlag
	Steps       []plugins.CommandStep
}

func getPluginManager() (*plugins.PluginManager, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	pm := plugins.NewPluginManager(filepath.Dir(exe))
	if err := pm.LoadPlugins(); err != nil {
		return nil, err
	}
	return pm, nil
}

func getMarketplaceCloud() (src.CloudProvider, error) {
	return src.GetCloudProvider("gdrive", context.Background(), src.GetDefaultCreds(), src.GetDefaultToken(), "apm_public")
}

func listInstalledPlugins() ([]string, error) {
	pm, err := getPluginManager()
	if err != nil {
		return nil, err
	}
	names := pm.ListPlugins()
	sort.Strings(names)
	return names, nil
}

func listMarketplacePlugins() ([]string, error) {
	cm, err := getMarketplaceCloud()
	if err != nil {
		return nil, err
	}
	names, err := cm.ListMarketplacePlugins()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func installMarketplacePlugin(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("plugin name is required")
	}
	pm, err := getPluginManager()
	if err != nil {
		return err
	}
	cm, err := getMarketplaceCloud()
	if err != nil {
		return err
	}
	targetDir := filepath.Join(pm.PluginsDir, name)
	if err := cm.DownloadPlugin(name, targetDir); err != nil {
		_ = os.RemoveAll(targetDir)
		return err
	}
	return nil
}

func installLocalPlugin(localPath string) (string, error) {
	localPath = strings.TrimSpace(localPath)
	if localPath == "" {
		return "", fmt.Errorf("local plugin path is required")
	}
	pluginJSON := filepath.Join(localPath, "plugin.json")
	if _, err := os.Stat(pluginJSON); err != nil {
		return "", fmt.Errorf("plugin.json not found at %s", pluginJSON)
	}
	def, err := plugins.LoadPluginDef(pluginJSON)
	if err != nil {
		return "", err
	}
	pm, err := getPluginManager()
	if err != nil {
		return "", err
	}
	if err := pm.InstallPlugin(def.Name, localPath); err != nil {
		return "", err
	}
	return def.Name, nil
}

func removeInstalledPlugin(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("plugin name is required")
	}
	pm, err := getPluginManager()
	if err != nil {
		return err
	}
	return pm.RemovePlugin(name)
}

func pushPluginToMarketplace(name, sourcePath string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("plugin name is required")
	}
	pm, err := getPluginManager()
	if err != nil {
		return err
	}
	if strings.TrimSpace(sourcePath) == "" {
		sourcePath = filepath.Join(pm.PluginsDir, name)
	}
	if _, err := os.Stat(filepath.Join(sourcePath, "plugin.json")); err != nil {
		return fmt.Errorf("invalid plugin source: plugin.json missing at %s", sourcePath)
	}
	cm, err := getMarketplaceCloud()
	if err != nil {
		return err
	}
	return cm.UploadPlugin(name, sourcePath)
}

func getInstalledPluginCommands(name string) ([]string, error) {
	specs, err := getInstalledPluginCommandSpecs(name)
	if err != nil {
		return nil, err
	}
	rows := make([]string, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec.Description) == "" {
			rows = append(rows, spec.Name)
		} else {
			rows = append(rows, fmt.Sprintf("%s - %s", spec.Name, spec.Description))
		}
	}
	return rows, nil
}

func getInstalledPluginCommandSpecs(name string) ([]PluginCommandSpec, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return []PluginCommandSpec{}, nil
	}
	pm, err := getPluginManager()
	if err != nil {
		return nil, err
	}
	p, ok := pm.Loaded[name]
	if !ok || p == nil || p.Definition == nil {
		return []PluginCommandSpec{}, nil
	}
	if len(p.Definition.Commands) == 0 {
		return []PluginCommandSpec{}, nil
	}

	keys := make([]string, 0, len(p.Definition.Commands))
	for k := range p.Definition.Commands {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	specs := make([]PluginCommandSpec, 0, len(keys))
	for _, k := range keys {
		def := p.Definition.Commands[k]
		specs = append(specs, PluginCommandSpec{
			Name:        k,
			Description: def.Description,
			Flags:       def.Flags,
			Steps:       def.Steps,
		})
	}
	return specs, nil
}

func executeInstalledPluginCommand(pluginName, commandName, flagArgs, masterPassword, vaultPath string) error {
	pluginName = strings.TrimSpace(pluginName)
	commandName = strings.TrimSpace(commandName)
	if pluginName == "" || commandName == "" {
		return fmt.Errorf("plugin and command are required")
	}
	pm, err := getPluginManager()
	if err != nil {
		return err
	}
	p, ok := pm.Loaded[pluginName]
	if !ok || p == nil || p.Definition == nil {
		return fmt.Errorf("plugin '%s' is not installed", pluginName)
	}
	cmdDef, ok := p.Definition.Commands[commandName]
	if !ok {
		return fmt.Errorf("command '%s' not found in plugin '%s'", commandName, pluginName)
	}
	for _, step := range cmdDef.Steps {
		if strings.EqualFold(strings.TrimSpace(step.Op), "s:in") {
			return fmt.Errorf("plugin command uses interactive step 's:in' which is not supported in TUI")
		}
	}

	data, err := src.LoadVault(vaultPath)
	if err != nil {
		return err
	}
	vault, err := src.DecryptVault(data, masterPassword, 1)
	if err != nil {
		return err
	}

	ctx := plugins.NewExecutionContext()
	for flagName, flagDef := range cmdDef.Flags {
		ctx.Variables[flagName] = flagDef.Default
	}
	overrides := parsePluginFlagArgs(flagArgs)
	for key, value := range overrides {
		ctx.Variables[key] = value
	}

	executor := plugins.NewStepExecutor(ctx, vault, vaultPath)
	if err := executor.ExecuteSteps(cmdDef.Steps, p.Definition.Permissions); err != nil {
		return err
	}
	return saveVault(vault, masterPassword, vaultPath)
}

func parsePluginFlagArgs(raw string) map[string]string {
	out := map[string]string{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	raw = strings.ReplaceAll(raw, ",", " ")
	tokens := strings.Fields(raw)
	for _, token := range tokens {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.TrimPrefix(parts[0], "--"))
		value := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		out[key] = value
	}
	return out
}
