//go:build windows

package autofillcmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const autofillAutostartTaskName = "APM Autofill"

func EnableAutofillAutostart(vaultPath, hotkey string) error {
	if strings.TrimSpace(vaultPath) == "" {
		return fmt.Errorf("vault path is required")
	}
	if strings.TrimSpace(hotkey) == "" {
		hotkey = "CTRL+SHIFT+L"
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmdLine := fmt.Sprintf("\"%s\" autofill daemon --vault \"%s\" --hotkey \"%s\"", exe, vaultPath, hotkey)
	_, err = runSchTasks("/Create", "/F", "/SC", "ONLOGON", "/TN", autofillAutostartTaskName, "/TR", cmdLine)
	return err
}

func DisableAutofillAutostart() error {
	_, err := runSchTasks("/Delete", "/TN", autofillAutostartTaskName, "/F")
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "cannot find the file specified") {
		return nil
	}
	return err
}

func AutofillAutostartEnabled() (bool, error) {
	_, err := runSchTasks("/Query", "/TN", autofillAutostartTaskName)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "cannot find the file specified") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func runSchTasks(args ...string) (string, error) {
	cmd := exec.Command("schtasks", args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(buf.String()), fmt.Errorf("%v: %s", err, strings.TrimSpace(buf.String()))
	}
	return strings.TrimSpace(buf.String()), nil
}
