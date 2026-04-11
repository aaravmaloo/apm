//go:build !windows

package autofill

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func captureActiveWindowContext() (WindowContext, error) {
	switch runtime.GOOS {
	case "darwin":
		return captureActiveWindowContextDarwin()
	case "linux":
		return captureActiveWindowContextLinux()
	default:
		return WindowContext{}, errors.New("active window capture is unsupported on this platform")
	}
}

func captureActiveWindowContextDarwin() (WindowContext, error) {
	appName, err := runCommandText("osascript", "-e", `tell application "System Events" to get name of first application process whose frontmost is true`)
	if err != nil {
		return WindowContext{}, err
	}
	title, _ := runCommandText("osascript", "-e", `tell application "System Events" to tell (first application process whose frontmost is true) to get name of front window`)
	domain, _ := darwinFrontmostBrowserDomain(strings.TrimSpace(appName))
	return WindowContext{
		WindowTitle: strings.TrimSpace(title),
		ProcessName: strings.ToLower(strings.TrimSpace(appName)),
		Domain:      domain,
		DomainHints: nonEmptyStrings(domain),
	}, nil
}

func captureActiveWindowContextLinux() (WindowContext, error) {
	windowID, err := runCommandText("xdotool", "getactivewindow")
	if err != nil {
		return WindowContext{}, err
	}
	windowID = strings.TrimSpace(windowID)
	if windowID == "" {
		return WindowContext{}, errors.New("unable to determine active window")
	}

	title, _ := runCommandText("xdotool", "getwindowname", windowID)
	pidText, _ := runCommandText("xdotool", "getwindowpid", windowID)
	pid, _ := strconv.Atoi(strings.TrimSpace(pidText))

	processPath := ""
	processName := ""
	if pid > 0 {
		if link, linkErr := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); linkErr == nil {
			processPath = link
			processName = strings.ToLower(filepath.Base(link))
		}
	}

	return WindowContext{
		WindowTitle: strings.TrimSpace(title),
		ProcessName: processName,
		ProcessPath: processPath,
	}, nil
}

func darwinFrontmostBrowserDomain(appName string) (string, error) {
	appName = strings.TrimSpace(appName)
	var script string
	switch appName {
	case "Google Chrome", "Brave Browser", "Microsoft Edge", "Arc":
		script = fmt.Sprintf(`tell application "%s" to get URL of active tab of front window`, escapeAppleScriptString(appName))
	case "Safari":
		script = `tell application "Safari" to get URL of front document`
	default:
		return "", nil
	}
	rawURL, err := runCommandText("osascript", "-e", script)
	if err != nil {
		return "", err
	}
	return domainFromURL(rawURL), nil
}

func domainFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return normalizeDomain(parsed.Hostname())
}

func runCommandText(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", errors.New(msg)
	}
	return strings.TrimSpace(out.String()), nil
}

func nonEmptyStrings(items ...string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
