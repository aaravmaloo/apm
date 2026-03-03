//go:build windows

package autofill

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/go-ole/go-ole"
	wa "github.com/hnakamur/w32uiautomation"
	"golang.org/x/sys/windows"
)

type uiaContext struct {
	FocusedName  string
	FocusedValue string
	EmailHints   []string
	DomainHints  []string
}

func readWindowUIHints(hwnd windows.HWND, windowTitle string) uiaContext {
	if hwnd == 0 {
		return uiaContext{}
	}

	resultCh := make(chan uiaContext, 1)
	go func() {
		resultCh <- readWindowUIHintsInternal(hwnd, windowTitle)
	}()

	select {
	case ctx := <-resultCh:
		return ctx
	case <-time.After(120 * time.Millisecond):
		return uiaContext{}
	}
}

func readWindowUIHintsInternal(hwnd windows.HWND, windowTitle string) uiaContext {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitialize(0); err != nil {
		return uiaContext{}
	}
	defer ole.CoUninitialize()

	auto, err := wa.NewUIAutomation()
	if err != nil {
		return uiaContext{}
	}
	defer auto.Release()

	collected := make([]string, 0, 8)
	ctx := uiaContext{}

	focused, err := getFocusedElement(auto)
	if err == nil && focused != nil {
		if name, nErr := focused.Get_CurrentName(); nErr == nil {
			ctx.FocusedName = strings.TrimSpace(name)
			if ctx.FocusedName != "" {
				collected = append(collected, ctx.FocusedName)
			}
		}
		value := elementStringProperty(focused, wa.UIA_ValueValuePropertyId)
		if value == "" {
			value = elementStringProperty(focused, wa.UIA_LegacyIAccessibleValuePropertyId)
		}
		ctx.FocusedValue = strings.TrimSpace(value)
		if ctx.FocusedValue != "" {
			collected = append(collected, ctx.FocusedValue)
		}
		focused.Release()
	}

	if len(extractEmailHints(collected)) > 0 {
		ctx.EmailHints = extractEmailHints(collected)
		ctx.DomainHints = extractDomainHints(collected)
		return ctx
	}

	if !looksLikeOTPWindow(windowTitle) && !looksLikeLoginWindow(windowTitle) {
		ctx.EmailHints = extractEmailHints(collected)
		ctx.DomainHints = extractDomainHints(collected)
		return ctx
	}

	root, err := elementFromHandle(auto, hwnd)
	if err == nil && root != nil {
		collected = append(collected, collectSubtreeHints(auto, root, 40, 2)...)
	}

	ctx.EmailHints = extractEmailHints(collected)
	ctx.DomainHints = extractDomainHints(collected)
	return ctx
}

func collectSubtreeHints(auto *wa.IUIAutomation, root *wa.IUIAutomationElement, maxNodes int, stopAfterEmails int) []string {
	walker, err := wa.NewTreeWalker(auto)
	if err != nil {
		root.Release()
		return nil
	}
	defer walker.Release()

	queue := []*wa.IUIAutomationElement{root}
	out := make([]string, 0, 16)
	visited := 0

	for len(queue) > 0 && visited < maxNodes {
		elem := queue[0]
		queue = queue[1:]
		visited++

		if name, err := elem.Get_CurrentName(); err == nil {
			name = strings.TrimSpace(name)
			if name != "" && len(name) <= 180 {
				out = append(out, name)
			}
		}

		value := elementStringProperty(elem, wa.UIA_ValueValuePropertyId)
		if value == "" {
			value = elementStringProperty(elem, wa.UIA_LegacyIAccessibleValuePropertyId)
		}
		if value != "" && len(value) <= 180 {
			out = append(out, value)
		}

		if stopAfterEmails > 0 && len(extractEmailHints(out)) >= stopAfterEmails {
			elem.Release()
			break
		}

		child, err := walker.GetFirstChildElement(elem)
		if err == nil && child != nil {
			queue = append(queue, child)
			next := child
			for {
				sibling, serr := walker.GetNextSiblingElement(next)
				if serr != nil || sibling == nil {
					break
				}
				queue = append(queue, sibling)
				next = sibling
			}
		}

		elem.Release()
	}

	for _, pending := range queue {
		pending.Release()
	}

	return out
}

func looksLikeLoginWindow(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	if title == "" {
		return false
	}
	keywords := []string{
		"sign in",
		"log in",
		"login",
		"password",
		"account",
		"authentication",
	}
	for _, kw := range keywords {
		if strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func elementStringProperty(elem *wa.IUIAutomationElement, id wa.PROPERTYID) string {
	v, err := elem.Get_CurrentPropertyValue(id)
	if err != nil {
		return ""
	}
	defer ole.VariantClear(&v)

	raw := v.Value()
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func getFocusedElement(auto *wa.IUIAutomation) (*wa.IUIAutomationElement, error) {
	var elem *wa.IUIAutomationElement
	hr, _, _ := syscall.Syscall(
		auto.VTable().GetFocusedElement,
		2,
		uintptr(unsafe.Pointer(auto)),
		uintptr(unsafe.Pointer(&elem)),
		0,
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}
	return elem, nil
}

func elementFromHandle(auto *wa.IUIAutomation, hwnd windows.HWND) (*wa.IUIAutomationElement, error) {
	var elem *wa.IUIAutomationElement
	hr, _, _ := syscall.Syscall(
		auto.VTable().ElementFromHandle,
		3,
		uintptr(unsafe.Pointer(auto)),
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&elem)),
	)
	if hr != 0 {
		return nil, ole.NewError(hr)
	}
	return elem, nil
}
