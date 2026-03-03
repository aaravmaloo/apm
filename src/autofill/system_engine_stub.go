//go:build !windows

package autofill

type noopSystemEngine struct{}

func newSystemEngine() SystemEngine {
	return &noopSystemEngine{}
}

func (n *noopSystemEngine) Name() string {
	return "unsupported"
}

func (n *noopSystemEngine) Start(h Hotkey, onHotkey func(WindowContext)) error {
	return nil
}

func (n *noopSystemEngine) Stop() error {
	return nil
}

func (n *noopSystemEngine) Type(actions []SequenceAction) error {
	return nil
}
