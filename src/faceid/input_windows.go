//go:build faceid && windows

package faceid

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const keyEvent = 0x0001

type inputRecord struct {
	EventType uint16
	_         uint16
	Event     [16]byte
}

type keyEventRecord struct {
	KeyDown          int32
	RepeatCount      uint16
	VirtualKeyCode   uint16
	VirtualScanCode  uint16
	UnicodeChar      uint16
	ControlKeyState  uint32
}

var (
	modkernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procPeekConsoleInput = modkernel32.NewProc("PeekConsoleInputW")
)

func peekConsoleInput(h windows.Handle, records *inputRecord, length uint32, read *uint32) error {
	r1, _, e1 := procPeekConsoleInput.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(records)),
		uintptr(length),
		uintptr(unsafe.Pointer(read)),
	)
	if r1 == 0 {
		if e1 != nil && e1 != syscall.Errno(0) {
			return e1
		}
		return syscall.EINVAL
	}
	return nil
}

func inputAvailable() bool {
	h := windows.Handle(os.Stdin.Fd())
	var n uint32
	if err := windows.GetNumberOfConsoleInputEvents(h, &n); err != nil || n == 0 {
		return false
	}
	if n > 64 {
		n = 64
	}
	records := make([]inputRecord, n)
	var read uint32
	if err := peekConsoleInput(h, &records[0], uint32(len(records)), &read); err != nil {
		return false
	}
	for i := 0; i < int(read); i++ {
		if records[i].EventType != keyEvent {
			continue
		}
		kev := (*keyEventRecord)(unsafe.Pointer(&records[i].Event[0]))
		if kev.KeyDown != 0 {
			return true
		}
	}
	return false
}
