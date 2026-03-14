//go:build windows

package autofill

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	vkShift   = 0x10
	vkControl = 0x11
	vkAlt     = 0x12
	vkTab     = 0x09
	vkEnter   = 0x0D

	keyeventfKeyUp   = 0x0002
	keyeventfUnicode = 0x0004
	inputKeyboard    = 1
)

var (
	user32DLL            = windows.NewLazySystemDLL("user32.dll")
	procGetAsyncKeyState = user32DLL.NewProc("GetAsyncKeyState")
	procGetWindowTextW   = user32DLL.NewProc("GetWindowTextW")
	procSendInput        = user32DLL.NewProc("SendInput")
)

type keyboardInput struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type input struct {
	Type    uint32
	_       uint32
	Ki      keyboardInput
	Padding uint64
}

type windowsSystemEngine struct {
	mu       sync.Mutex
	typeMu   sync.Mutex
	stopCh   chan struct{}
	stopped  bool
	hotkey   Hotkey
	callback func(WindowContext)
}

func newSystemEngine() SystemEngine {
	return &windowsSystemEngine{}
}

func (w *windowsSystemEngine) Name() string {
	return "windows-sendinput"
}

func (w *windowsSystemEngine) Start(h Hotkey, onHotkey func(WindowContext)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopCh != nil {
		return errors.New("system engine already running")
	}
	w.hotkey = h
	w.callback = onHotkey
	w.stopCh = make(chan struct{})
	go w.pollHotkey()
	return nil
}

func (w *windowsSystemEngine) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopCh == nil || w.stopped {
		return nil
	}
	close(w.stopCh)
	w.stopped = true
	return nil
}

func (w *windowsSystemEngine) Type(actions []SequenceAction) error {
	w.typeMu.Lock()
	defer w.typeMu.Unlock()

	w.waitForModifierRelease(500 * time.Millisecond)

	for _, action := range actions {
		switch action.Type {
		case ActionText:
			if err := typeText(action.Text); err != nil {
				return err
			}
		case ActionTab:
			if err := pressVirtualKey(vkTab); err != nil {
				return err
			}
		case ActionEnter:
			if err := pressVirtualKey(vkEnter); err != nil {
				return err
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func (w *windowsSystemEngine) pollHotkey() {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	wasDown := false
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			down := w.hotkeyPressed()
			if down && !wasDown {
				go w.dispatchHotkey()
			}
			wasDown = down
		}
	}
}

func (w *windowsSystemEngine) dispatchHotkey() {

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case <-w.stopCh:
			return
		default:
		}
		if !w.hotkeyPressed() && !isKeyDown(vkControl) && !isKeyDown(vkShift) && !isKeyDown(vkAlt) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(15 * time.Millisecond)

	ctx, err := getActiveWindowContext()
	if err == nil && w.callback != nil {
		w.callback(ctx)
	}
}

func (w *windowsSystemEngine) waitForModifierRelease(maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if !isKeyDown(vkControl) && !isKeyDown(vkShift) && !isKeyDown(vkAlt) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (w *windowsSystemEngine) hotkeyPressed() bool {
	if w.hotkey.Ctrl && !isKeyDown(vkControl) {
		return false
	}
	if w.hotkey.Alt && !isKeyDown(vkAlt) {
		return false
	}
	if w.hotkey.Shift && !isKeyDown(vkShift) {
		return false
	}
	vk := hotkeyKeyToVK(w.hotkey.Key)
	if vk == 0 {
		return false
	}
	return isKeyDown(vk)
}

func hotkeyKeyToVK(key string) uint16 {
	if key == "" {
		return 0
	}
	r := []rune(strings.ToUpper(strings.TrimSpace(key)))
	if len(r) != 1 {
		return 0
	}
	if unicode.IsLetter(r[0]) || unicode.IsDigit(r[0]) {
		return uint16(r[0])
	}
	return 0
}

func isKeyDown(vk uint16) bool {
	ret, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return ret&0x8000 != 0
}

func getActiveWindowContext() (WindowContext, error) {
	hwnd := windows.GetForegroundWindow()
	if hwnd == 0 {
		return WindowContext{}, errors.New("no active window")
	}

	title, err := getWindowTitle(hwnd)
	if err != nil {
		return WindowContext{}, err
	}

	var pid uint32
	_, err = windows.GetWindowThreadProcessId(hwnd, &pid)
	if err != nil {
		return WindowContext{}, err
	}

	processPath, err := queryProcessPath(pid)
	if err != nil {
		return WindowContext{}, err
	}

	uiaCtx := readWindowUIHints(hwnd, title)
	domain := ""
	if len(uiaCtx.DomainHints) > 0 {
		domain = uiaCtx.DomainHints[0]
	}

	return WindowContext{
		WindowTitle:  title,
		ProcessName:  strings.ToLower(filepath.Base(processPath)),
		ProcessPath:  processPath,
		Domain:       domain,
		DomainHints:  uiaCtx.DomainHints,
		FocusedName:  uiaCtx.FocusedName,
		FocusedValue: uiaCtx.FocusedValue,
		EmailHints:   uiaCtx.EmailHints,
	}, nil
}

func getWindowTitle(hwnd windows.HWND) (string, error) {
	buf := make([]uint16, 512)
	ret, _, err := procGetWindowTextW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if ret == 0 {
		return "", err
	}
	return windows.UTF16ToString(buf[:ret]), nil
}

func queryProcessPath(pid uint32) (string, error) {
	const processQueryLimitedInformation = 0x1000
	handle, err := windows.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func typeText(text string) error {
	for _, r := range text {
		if err := typeRune(r); err != nil {
			return err
		}
		time.Sleep(8 * time.Millisecond)
	}
	return nil
}

func typeRune(r rune) error {
	units := utf16.Encode([]rune{r})
	inputs := make([]input, 0, len(units)*2)
	for _, unit := range units {
		inputs = append(inputs, input{
			Type: inputKeyboard,
			Ki: keyboardInput{
				WVk:     0,
				WScan:   unit,
				DwFlags: keyeventfUnicode,
			},
		})
		inputs = append(inputs, input{
			Type: inputKeyboard,
			Ki: keyboardInput{
				WVk:     0,
				WScan:   unit,
				DwFlags: keyeventfUnicode | keyeventfKeyUp,
			},
		})
	}
	return sendInputs(inputs)
}

func pressVirtualKey(vk uint16) error {
	inputs := []input{
		{
			Type: inputKeyboard,
			Ki: keyboardInput{
				WVk:     vk,
				WScan:   0,
				DwFlags: 0,
			},
		},
		{
			Type: inputKeyboard,
			Ki: keyboardInput{
				WVk:     vk,
				WScan:   0,
				DwFlags: keyeventfKeyUp,
			},
		},
	}
	return sendInputs(inputs)
}

func sendInputs(inputs []input) error {
	if len(inputs) == 0 {
		return nil
	}

	ret, _, callErr := procSendInput.Call(
		uintptr(len(inputs)),
		uintptr(unsafe.Pointer(&inputs[0])),
		unsafe.Sizeof(inputs[0]),
	)
	if ret != uintptr(len(inputs)) {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return callErr
		}
		return errors.New("send input failed")
	}
	return nil
}
