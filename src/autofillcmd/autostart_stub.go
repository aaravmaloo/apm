//go:build !windows

package autofillcmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func EnableAutofillAutostart(vaultPath, hotkey, mailHotkey string) error {
	switch runtime.GOOS {
	case "linux":
		return enableLinuxAutostart(vaultPath, hotkey, mailHotkey)
	case "darwin":
		return enableDarwinAutostart(vaultPath, hotkey, mailHotkey)
	default:
		return errors.New("autostart is unsupported on this platform")
	}
}

func DisableAutofillAutostart() error {
	switch runtime.GOOS {
	case "linux":
		return disableLinuxAutostart()
	case "darwin":
		return disableDarwinAutostart()
	default:
		return errors.New("autostart is unsupported on this platform")
	}
}

func AutofillAutostartEnabled() (bool, error) {
	switch runtime.GOOS {
	case "linux":
		return linuxAutostartEnabled()
	case "darwin":
		return darwinAutostartEnabled()
	default:
		return false, errors.New("autostart is unsupported on this platform")
	}
}

func enableLinuxAutostart(vaultPath, hotkey, mailHotkey string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	servicePath, err := linuxAutostartServicePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(servicePath), 0700); err != nil {
		return err
	}

	unit := fmt.Sprintf(`[Unit]
Description=APM Autofill Daemon
After=default.target

[Service]
Type=simple
ExecStart=%s autofill daemon --vault %s --hotkey %s --mail-hotkey %s
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
`, quoteSystemdArg(exe), quoteSystemdArg(vaultPath), quoteSystemdArg(defaultHotkey(hotkey)), quoteSystemdArg(defaultMailHotkey(mailHotkey)))
	if err := os.WriteFile(servicePath, []byte(unit), 0600); err != nil {
		return err
	}
	if err := runQuiet("systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	return runQuiet("systemctl", "--user", "enable", "--now", "apm-autofill.service")
}

func disableLinuxAutostart() error {
	_ = runQuiet("systemctl", "--user", "disable", "--now", "apm-autofill.service")
	servicePath, err := linuxAutostartServicePath()
	if err != nil {
		return err
	}
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return runQuiet("systemctl", "--user", "daemon-reload")
}

func linuxAutostartEnabled() (bool, error) {
	servicePath, err := linuxAutostartServicePath()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(servicePath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func linuxAutostartServicePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "systemd", "user", "apm-autofill.service"), nil
}

func enableDarwinAutostart(vaultPath, hotkey, mailHotkey string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	plistPath, err := darwinAutostartPlistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0700); err != nil {
		return err
	}
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.aaravmaloo.apm.autofill</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>autofill</string>
    <string>daemon</string>
    <string>--vault</string>
    <string>%s</string>
    <string>--hotkey</string>
    <string>%s</string>
    <string>--mail-hotkey</string>
    <string>%s</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
`, xmlEscape(exe), xmlEscape(vaultPath), xmlEscape(defaultHotkey(hotkey)), xmlEscape(defaultMailHotkey(mailHotkey)))
	if err := os.WriteFile(plistPath, []byte(plist), 0600); err != nil {
		return err
	}
	_ = runQuiet("launchctl", "unload", plistPath)
	return runQuiet("launchctl", "load", plistPath)
}

func disableDarwinAutostart() error {
	plistPath, err := darwinAutostartPlistPath()
	if err != nil {
		return err
	}
	_ = runQuiet("launchctl", "unload", plistPath)
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func darwinAutostartEnabled() (bool, error) {
	plistPath, err := darwinAutostartPlistPath()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(plistPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func darwinAutostartPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", "com.aaravmaloo.apm.autofill.plist"), nil
}

func quoteSystemdArg(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(value)
}

func defaultHotkey(hotkey string) string {
	if strings.TrimSpace(hotkey) == "" {
		return "CTRL+SHIFT+L"
	}
	return strings.TrimSpace(hotkey)
}

func defaultMailHotkey(hotkey string) string {
	if strings.TrimSpace(hotkey) == "" {
		return "CTRL+SHIFT+P"
	}
	return strings.TrimSpace(hotkey)
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}
