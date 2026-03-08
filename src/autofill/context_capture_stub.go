//go:build !windows

package autofill

import "errors"

func captureActiveWindowContext() (WindowContext, error) {
	return WindowContext{}, errors.New("active window capture is only supported on windows")
}
