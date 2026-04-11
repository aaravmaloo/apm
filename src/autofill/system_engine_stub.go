//go:build !windows

package autofill

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type noopSystemEngine struct{}

func newSystemEngine() SystemEngine {
	return &noopSystemEngine{}
}

func (n *noopSystemEngine) Name() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin-osascript"
	case "linux":
		return "linux-xdotool"
	default:
		return "unsupported"
	}
}

func (n *noopSystemEngine) Start(primary Hotkey, onPrimary func(WindowContext), mail Hotkey, onMail func(WindowContext)) error {
	return nil
}

func (n *noopSystemEngine) Stop() error {
	return nil
}

func (n *noopSystemEngine) Type(actions []SequenceAction) error {
	switch runtime.GOOS {
	case "darwin":
		return typeWithAppleScript(actions)
	case "linux":
		return typeWithXDoTool(actions)
	default:
		return nil
	}
}

func typeWithAppleScript(actions []SequenceAction) error {
	for _, action := range actions {
		var script string
		switch action.Type {
		case ActionText:
			script = fmt.Sprintf(`tell application "System Events" to keystroke "%s"`, escapeAppleScriptString(action.Text))
		case ActionTab:
			script = `tell application "System Events" to key code 48`
		case ActionEnter:
			script = `tell application "System Events" to key code 36`
		default:
			continue
		}
		if err := exec.Command("osascript", "-e", script).Run(); err != nil {
			return err
		}
		time.Sleep(12 * time.Millisecond)
	}
	return nil
}

func typeWithXDoTool(actions []SequenceAction) error {
	for _, action := range actions {
		var cmd *exec.Cmd
		switch action.Type {
		case ActionText:
			cmd = exec.Command("xdotool", "type", "--clearmodifiers", "--delay", "8", action.Text)
		case ActionTab:
			cmd = exec.Command("xdotool", "key", "--clearmodifiers", "Tab")
		case ActionEnter:
			cmd = exec.Command("xdotool", "key", "--clearmodifiers", "Return")
		default:
			continue
		}
		if err := cmd.Run(); err != nil {
			return err
		}
		time.Sleep(12 * time.Millisecond)
	}
	return nil
}

func escapeAppleScriptString(input string) string {
	replacer := strings.NewReplacer(
		`\\`, `\\\\`,
		`"`, `\"`,
	)
	return replacer.Replace(input)
}

func formatKeyCode(code int) string {
	return strconv.Itoa(code)
}
