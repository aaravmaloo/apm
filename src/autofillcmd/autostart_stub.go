//go:build !windows

package autofillcmd

import "errors"

func EnableAutofillAutostart(vaultPath, hotkey string) error {
	return errors.New("autostart is only supported on Windows")
}

func DisableAutofillAutostart() error {
	return errors.New("autostart is only supported on Windows")
}

func AutofillAutostartEnabled() (bool, error) {
	return false, errors.New("autostart is only supported on Windows")
}
