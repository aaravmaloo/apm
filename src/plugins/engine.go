package plugins

import (
	"fmt"
	"strings"
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
}

func NewStepExecutor(ctx *ExecutionContext) *StepExecutor {
	return &StepExecutor{Context: ctx}
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

		key := se.Context.Substitute(step.Key)
		secretValue := "MOCK_SECRET_FOR_" + key

		if step.AssignTo != "" {
			se.Context.Variables[step.AssignTo] = secretValue
		}
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
