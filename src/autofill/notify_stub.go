//go:build !windows

package autofill

type PopupNotifier interface {
	Show(message string)
}

type noopPopupNotifier struct{}

func (noopPopupNotifier) Show(string) {}

func newPopupNotifier() PopupNotifier {
	return noopPopupNotifier{}
}
