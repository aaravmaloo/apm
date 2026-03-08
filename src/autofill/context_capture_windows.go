//go:build windows

package autofill

func captureActiveWindowContext() (WindowContext, error) {
	return getActiveWindowContext()
}
