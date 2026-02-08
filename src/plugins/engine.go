package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	apm "password-manager/src"
)

type ExecutionContext struct {
	Variables map[string]string
	Output    []string
}

func NewExecutionContext() *ExecutionContext {
	return &ExecutionContext{
		Variables: make(map[string]string),
	}
}

func (ctx *ExecutionContext) Substitute(input string) string {
	result := input
	for k, v := range ctx.Variables {
		placeholder := fmt.Sprintf("{{%s}}", k)
		result = strings.ReplaceAll(result, placeholder, v)
	}
	return result
}

type StepExecutor struct {
	Context   *ExecutionContext
	Vault     *apm.Vault
	VaultPath string
}

func NewStepExecutor(ctx *ExecutionContext, vault *apm.Vault, vaultPath string) *StepExecutor {
	return &StepExecutor{Context: ctx, Vault: vault, VaultPath: vaultPath}
}

func (se *StepExecutor) ExecuteSteps(steps []CommandStep, permissions []string) error {
	for _, step := range steps {
		if err := se.ExecuteStep(step, permissions); err != nil {
			return err
		}
	}
	return nil
}

func (se *StepExecutor) getArg(args []string, idx int) string {
	if idx < len(args) {
		return se.Context.Substitute(args[idx])
	}
	return ""
}

func (se *StepExecutor) ExecuteStep(step CommandStep, permissions []string) error {
	switch step.Op {
	case "s:out":
		fmt.Println(se.getArg(step.Args, 0))
		return nil

	case "v:get":
		if !hasPermission(permissions, "vault.read") {
			return fmt.Errorf("permission denied: vault.read")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.getArg(step.Args, 0)
		assignTo := se.getArg(step.Args, 1)

		var val string
		for _, e := range se.Vault.Entries {
			if e.Account == key {
				val = e.Password
				break
			}
		}
		if val == "" {
			for _, t := range se.Vault.Tokens {
				if t.Name == key {
					val = t.Token
					break
				}
			}
		}
		if val == "" {
			for _, t := range se.Vault.TOTPEntries {
				if t.Account == key {
					val = t.Secret // In a real app we might want to generate the code here
					break
				}
			}
		}

		if assignTo != "" {
			se.Context.Variables[assignTo] = val
		}
		return nil

	case "v:add":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		account := se.getArg(step.Args, 0)
		password := se.getArg(step.Args, 1)
		username := se.getArg(step.Args, 2)
		if username == "" {
			username = "plugin_user"
		}
		return se.Vault.AddEntry(account, username, password)

	case "v:list":
		if !hasPermission(permissions, "vault.read") {
			return fmt.Errorf("permission denied: vault.read")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		assignTo := se.getArg(step.Args, 0)
		var names []string
		for _, e := range se.Vault.Entries {
			names = append(names, e.Account)
		}
		if assignTo != "" {
			se.Context.Variables[assignTo] = strings.Join(names, ", ")
		}
		return nil

	case "v:del":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.getArg(step.Args, 0)
		if se.Vault.DeleteEntry(key) {
			return nil
		}
		return fmt.Errorf("entry '%s' not found", key)

	case "s:clip":
		if !hasPermission(permissions, "system.write") {
			return fmt.Errorf("permission denied: system.write")
		}
		text := se.getArg(step.Args, 0)
		fmt.Printf("[CLIPBOARD] %s\n", text)
		return nil

	case "s:in":
		fmt.Printf("%s: ", se.getArg(step.Args, 0))
		assignTo := se.getArg(step.Args, 1)
		var input string
		_, _ = fmt.Scanln(&input)
		if assignTo != "" {
			se.Context.Variables[assignTo] = input
		}
		return nil

	case "net:get":
		if !hasPermission(permissions, "network.outbound") {
			return fmt.Errorf("permission denied: network.outbound")
		}
		url := se.getArg(step.Args, 0)
		assignTo := se.getArg(step.Args, 1)
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if assignTo != "" {
			se.Context.Variables[assignTo] = string(body)
		}
		return nil

	case "net:post":
		if !hasPermission(permissions, "network.outbound") {
			return fmt.Errorf("permission denied: network.outbound")
		}
		url := se.getArg(step.Args, 0)
		payload := se.getArg(step.Args, 1)
		assignTo := se.getArg(step.Args, 2)
		resp, err := http.Post(url, "application/json", strings.NewReader(payload))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if assignTo != "" {
			se.Context.Variables[assignTo] = string(body)
		}
		return nil

	case "crypto:hash":
		if !hasPermission(permissions, "crypto.use") {
			return fmt.Errorf("permission denied: crypto.use")
		}
		data := se.getArg(step.Args, 0)
		assignTo := se.getArg(step.Args, 1)
		hash := sha256.Sum256([]byte(data))
		if assignTo != "" {
			se.Context.Variables[assignTo] = hex.EncodeToString(hash[:])
		}
		return nil

	case "v:backup":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write")
		}
		vaultData, err := os.ReadFile(se.VaultPath)
		if err != nil {
			return err
		}
		backupPath := fmt.Sprintf("%s.backup_%d", se.VaultPath, time.Now().Unix())
		return os.WriteFile(backupPath, vaultData, 0600)

	case "s:sleep":
		seconds := se.getArg(step.Args, 0)
		d, _ := time.ParseDuration(seconds + "s")
		time.Sleep(d)
		return nil

	case "c:sync":
		if !hasPermission(permissions, "cloud.sync") {
			return fmt.Errorf("permission denied: cloud.sync")
		}
		fmt.Println("Triggering cloud sync...")
		// In a real app we would call the sync logic here.
		// For now we just simulate.
		return nil

	case "v:lock":
		fmt.Println("Vault lock signal received.")
		return nil

	case "v:export":
		if !hasPermission(permissions, "vault.export") {
			return fmt.Errorf("permission denied: vault.export")
		}
		format := se.getArg(step.Args, 0)
		path := se.getArg(step.Args, 1)
		// Dummy implementation for export
		fmt.Printf("Exporting vault to %s in %s format...\n", path, format)
		return nil

	case "s:exec":
		if !hasPermission(permissions, "system.exec") {
			return fmt.Errorf("permission denied: system.exec")
		}
		cmdName := se.getArg(step.Args, 0)
		cmdArgsStr := se.getArg(step.Args, 1)
		assignTo := se.getArg(step.Args, 2)

		cmdArgs := strings.Fields(cmdArgsStr)
		cmd := exec.Command(cmdName, cmdArgs...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("exec failed: %w: %s", err, string(out))
		}
		if assignTo != "" {
			se.Context.Variables[assignTo] = string(out)
		}
		return nil

	default:
		return fmt.Errorf("unknown op: %s", step.Op)
	}
}

func hasPermission(perms []string, required string) bool {
	for _, p := range perms {
		if p == "*" {
			return true
		}
		if p == required {
			return true
		}
		if strings.HasSuffix(p, ".*") {
			prefix := strings.TrimSuffix(p, ".*")
			if strings.HasPrefix(required, prefix+".") {
				return true
			}
		}
	}
	return false
}

func (pm *PluginManager) ExecuteHooks(event, command string, vault *apm.Vault, vaultPath string) error {
	hookKey := fmt.Sprintf("%s:%s", event, command)
	ctx := NewExecutionContext()
	se := NewStepExecutor(ctx, vault, vaultPath)

	for _, plugin := range pm.Loaded {
		if actions, ok := plugin.Definition.Hooks[hookKey]; ok {
			for _, action := range actions {
				if err := se.ExecuteStep(CommandStep(action), plugin.Definition.Permissions); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
