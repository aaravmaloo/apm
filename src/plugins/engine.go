package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
	Context *ExecutionContext
	Vault   *apm.Vault
}

func NewStepExecutor(ctx *ExecutionContext, vault *apm.Vault) *StepExecutor {
	return &StepExecutor{Context: ctx, Vault: vault}
}

func (se *StepExecutor) ExecuteSteps(steps []CommandStep, permissions []string) error {
	for _, step := range steps {
		if err := se.ExecuteStep(step, permissions); err != nil {
			return err
		}
	}
	return nil
}

func (se *StepExecutor) ExecuteStep(step CommandStep, permissions []string) error {

	switch step.Action {
	case "print":
		msg := se.Context.Substitute(step.Message)
		fmt.Println(msg)
		return nil

	case "vault.get":
		if !hasPermission(permissions, "vault.read") {
			return fmt.Errorf("permission denied: vault.read required for vault.get")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.Context.Substitute(step.Key)

		var secretValue string
		for _, e := range se.Vault.Entries {
			if e.Account == key {
				secretValue = e.Password
				break
			}
		}

		if secretValue == "" {
			for _, t := range se.Vault.Tokens {
				if t.Name == key {
					secretValue = t.Token
					break
				}
			}
		}

		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = secretValue
		}
		return nil

	case "vault.add":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write required for vault.add")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		name := se.Context.Substitute(step.Key)
		val := se.Context.Substitute(step.Message)
		se.Vault.AddEntry(name, "plugin_user", val)
		return nil

	case "vault.list":
		if !hasPermission(permissions, "vault.read") {
			return fmt.Errorf("permission denied: vault.read")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		var names []string
		for _, e := range se.Vault.Entries {
			names = append(names, e.Account)
		}
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = strings.Join(names, ", ")
		}
		return nil

	case "system.copy":
		if !hasPermission(permissions, "system.write") {
			return fmt.Errorf("permission denied: system.write")
		}
		text := se.Context.Substitute(step.Message)
		fmt.Printf("[CLIPBOARD] %s\n", text)
		return nil

	case "prompt.input":
		fmt.Printf("%s: ", se.Context.Substitute(step.Message))
		var input string
		fmt.Scanln(&input)
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = input
		}
		return nil

	case "vault.delete":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.Context.Substitute(step.Key)
		if se.Vault.DeleteEntry(key) {
			return nil
		}
		return fmt.Errorf("entry '%s' not found", key)

	case "network.get":
		if !hasPermission(permissions, "network.outbound") {
			return fmt.Errorf("permission denied: network.outbound")
		}
		url := se.Context.Substitute(step.Key)
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = string(body)
		}
		return nil

	case "network.post":
		if !hasPermission(permissions, "network.outbound") {
			return fmt.Errorf("permission denied: network.outbound")
		}
		url := se.Context.Substitute(step.Key)
		payload := se.Context.Substitute(step.Message)
		resp, err := http.Post(url, "application/json", strings.NewReader(payload))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = string(body)
		}
		return nil

	case "vault.edit":
		if !hasPermission(permissions, "vault.write") {
			return fmt.Errorf("permission denied: vault.write")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.Context.Substitute(step.Key)
		val := se.Context.Substitute(step.Message)
		for i, e := range se.Vault.Entries {
			if e.Account == key {
				se.Vault.Entries[i].Password = val
				return nil
			}
		}
		return fmt.Errorf("entry '%s' not found", key)

	case "vault.get_totp":
		if !hasPermission(permissions, "vault.read") {
			return fmt.Errorf("permission denied: vault.read")
		}
		if se.Vault == nil {
			return fmt.Errorf("vault not available")
		}
		key := se.Context.Substitute(step.Key)
		for _, t := range se.Vault.TOTPEntries {
			if t.Account == key {
				se.Context.Variables[step.AssignTo] = "TOTP_FOR_" + t.Secret
				return nil
			}
		}
		return fmt.Errorf("TOTP entry '%s' not found", key)

	case "system.env":
		if !hasPermission(permissions, "system.read") {
			return fmt.Errorf("permission denied: system.read")
		}
		key := se.Context.Substitute(step.Key)
		val := os.Getenv(key)
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = val
		}
		return nil

	case "crypto.hash":
		if !hasPermission(permissions, "crypto.use") {
			return fmt.Errorf("permission denied: crypto.use")
		}
		data := se.Context.Substitute(step.Message)
		hash := sha256.Sum256([]byte(data))
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = hex.EncodeToString(hash[:])
		}
		return nil

	case "system.info":
		if !hasPermission(permissions, "system.read") {
			return fmt.Errorf("permission denied: system.read")
		}
		info := fmt.Sprintf("OS: %s, User: %s", se.Context.Variables["OS"], se.Context.Variables["USER"])
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = info
		}
		return nil

	case "prompt.confirm":
		fmt.Printf("%s (y/n): ", se.Context.Substitute(step.Message))
		var input string
		fmt.Scanln(&input)
		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = strings.ToLower(input)
		}
		return nil

	case "vault.lock":
		fmt.Println("Lock signal received from plugin.")
		return nil

	case "file.storage":

		if !hasPermission(permissions, "file.storage") {
			return fmt.Errorf("permission denied: file.storage")
		}
		return nil

	default:
		return fmt.Errorf("unknown action: %s", step.Action)
	}
}

func hasPermission(perms []string, required string) bool {
	for _, p := range perms {
		if p == required {
			return true
		}
	}
	return false
}

func (pm *PluginManager) ExecuteHooks(event, command string, data map[string]interface{}) error {
	hookKey := fmt.Sprintf("%s:%s", event, command)

	for _, plugin := range pm.Loaded {
		if actions, ok := plugin.Definition.Hooks[hookKey]; ok {
			for _, action := range actions {

				if err := pm.runHookAction(action); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (pm *PluginManager) runHookAction(action HookAction) error {
	switch action.Action {
	case "validate.file":

		return nil
	case "validate.file_type":
		return nil
	default:
		return fmt.Errorf("unknown hook action: %s", action.Action)
	}
}
