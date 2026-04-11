//go:build windows

package autofillcmd

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const autofillAutostartValueName = "APM Autofill"
const autofillRunKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

func EnableAutofillAutostart(vaultPath, hotkey, mailHotkey string) error {
	if strings.TrimSpace(vaultPath) == "" {
		return fmt.Errorf("vault path is required")
	}
	if strings.TrimSpace(hotkey) == "" {
		hotkey = "CTRL+SHIFT+L"
	}
	if strings.TrimSpace(mailHotkey) == "" {
		mailHotkey = "CTRL+SHIFT+P"
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	cmdLine := fmt.Sprintf("\"%s\" autofill daemon --vault \"%s\" --hotkey \"%s\" --mail-hotkey \"%s\"", exe, vaultPath, hotkey, mailHotkey)
	key, _, err := registry.CreateKey(registry.CURRENT_USER, autofillRunKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(autofillAutostartValueName, cmdLine)
}

func DisableAutofillAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, autofillRunKeyPath, registry.SET_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}
	defer key.Close()
	err = key.DeleteValue(autofillAutostartValueName)
	if err == registry.ErrNotExist {
		return nil
	}
	return err
}

func AutofillAutostartEnabled() (bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, autofillRunKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(autofillAutostartValueName)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(value) != "", nil
}
