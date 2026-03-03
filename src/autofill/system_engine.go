package autofill

import (
	"fmt"
	"strings"
	"unicode"
)

type WindowContext struct {
	WindowTitle  string
	ProcessName  string
	ProcessPath  string
	Domain       string
	DomainHints  []string
	FocusedName  string
	FocusedValue string
	EmailHints   []string
}

type Hotkey struct {
	Ctrl  bool
	Alt   bool
	Shift bool
	Key   string
}

type SystemEngine interface {
	Name() string
	Start(h Hotkey, onHotkey func(WindowContext)) error
	Stop() error
	Type(actions []SequenceAction) error
}

func parseHotkey(input string) (Hotkey, error) {
	if strings.TrimSpace(input) == "" {
		input = "CTRL+SHIFT+ALT+A"
	}
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(input)), "+")
	if len(parts) < 2 {
		return Hotkey{}, fmt.Errorf("invalid hotkey: %s", input)
	}

	var hk Hotkey
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "CTRL", "CONTROL":
			hk.Ctrl = true
		case "ALT":
			hk.Alt = true
		case "SHIFT":
			hk.Shift = true
		default:
			if len([]rune(part)) == 1 && unicode.IsPrint([]rune(part)[0]) {
				hk.Key = part
				continue
			}
			return Hotkey{}, fmt.Errorf("unsupported hotkey token: %s", part)
		}
	}

	if hk.Key == "" {
		return Hotkey{}, fmt.Errorf("invalid hotkey: missing key")
	}
	if !hk.Ctrl && !hk.Alt && !hk.Shift {
		return Hotkey{}, fmt.Errorf("invalid hotkey: at least one modifier is required")
	}
	return hk, nil
}
