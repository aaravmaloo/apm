package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// noteEditorKey converts a short key name into a tea.KeyMsg for tests.
func noteEditorKey(s string) tea.KeyMsg {
	switch s {
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "ctrl+z":
		return tea.KeyMsg{Type: tea.KeyCtrlZ}
	case "ctrl+y":
		return tea.KeyMsg{Type: tea.KeyCtrlY}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// sendNoteKeys feeds keystrokes through the model and returns the final model.
func sendNoteKeys(t *testing.T, m noteEditorModel, keys ...string) noteEditorModel {
	t.Helper()
	var model tea.Model = m
	for _, k := range keys {
		var cmd tea.Cmd
		model, cmd = model.Update(noteEditorKey(k))
		_ = cmd
	}
	fm, ok := model.(noteEditorModel)
	if !ok {
		t.Fatalf("unexpected model type %T", model)
	}
	return fm
}

func TestNoteEditorTypingAndSave(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("My Note", "personal", ""),
		"h", "e", "l", "l", "o", " ", "w", "o", "r", "l", "d",
		"ctrl+s")
	if !m.done {
		t.Fatal("expected editor to quit after save")
	}
	if m.cancelled {
		t.Fatal("save should not be treated as cancel")
	}
	if m.result != "hello world" {
		t.Fatalf("expected saved content %q, got %q", "hello world", m.result)
	}
}

func TestNoteEditorSaveUntouchedContent(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", "existing content\nline two"), "ctrl+s")
	if m.result != "existing content\nline two" {
		t.Fatalf("expected content preserved, got %q", m.result)
	}
}

func TestNoteEditorMultiLineTyping(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""),
		"a", "enter", "b", "enter", "c", "ctrl+s")
	if m.result != "a\nb\nc" {
		t.Fatalf("expected multi-line content %q, got %q", "a\nb\nc", m.result)
	}
}

func TestNoteEditorEscWithoutChangesCancelsImmediately(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""), "esc")
	if !m.done || !m.cancelled {
		t.Fatalf("expected immediate cancel, done=%v cancelled=%v", m.done, m.cancelled)
	}
}

func TestNoteEditorEscWithChangesRequiresConfirmation(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""), "x", "esc")
	if m.done {
		t.Fatal("first esc with unsaved changes should not quit")
	}
	if !m.confirming {
		t.Fatal("expected confirm-discard state after first esc")
	}
	m = sendNoteKeys(t, m, "esc")
	if !m.done || !m.cancelled {
		t.Fatalf("expected second esc to discard and cancel, done=%v cancelled=%v", m.done, m.cancelled)
	}
}

func TestNoteEditorEscThenAnyKeyKeepsEditing(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""), "x", "esc", "y", "ctrl+s")
	if m.cancelled {
		t.Fatal("editing should continue after dismissing the confirm prompt")
	}
	if m.result != "xy" {
		t.Fatalf("expected both chars kept, got %q", m.result)
	}
}

func TestNoteEditorCtrlCBehavesLikeEsc(t *testing.T) {
	// No changes: cancel immediately.
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""), "ctrl+c")
	if !m.done || !m.cancelled {
		t.Fatalf("expected ctrl+c to cancel, done=%v cancelled=%v", m.done, m.cancelled)
	}
	// With changes: confirm first.
	m = sendNoteKeys(t, newNoteEditorModel("Note", "", ""), "x", "ctrl+c")
	if m.done || !m.confirming {
		t.Fatal("expected confirm-discard state after ctrl+c with changes")
	}
	m = sendNoteKeys(t, m, "ctrl+c")
	if !m.done || !m.cancelled {
		t.Fatalf("expected second ctrl+c to discard, done=%v cancelled=%v", m.done, m.cancelled)
	}
}

func TestNoteEditorUndoRedo(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""),
		"a", "b", "c", "ctrl+z", "ctrl+s")
	if m.result != "ab" {
		t.Fatalf("expected undo to remove last char, got %q", m.result)
	}

	m = sendNoteKeys(t, newNoteEditorModel("Note", "", ""),
		"a", "b", "c", "ctrl+z", "ctrl+y", "ctrl+s")
	if m.result != "abc" {
		t.Fatalf("expected redo to restore char, got %q", m.result)
	}
}

func TestNoteEditorUndoRestoresCursorPosition(t *testing.T) {
	m := sendNoteKeys(t, newNoteEditorModel("Note", "", ""),
		"a", "enter", "b", "b", "enter", "c", "c", "c",
		"up", // cursor to line 1
		"x",  // edit line 1: "a\nbbx\nccc"
		"ctrl+z",
	)
	if m.ta.Value() != "a\nbb\nccc" {
		t.Fatalf("expected undo to restore value, got %q", m.ta.Value())
	}
	if m.ta.Line() != 1 {
		t.Fatalf("expected cursor back on line 1, got %d", m.ta.Line())
	}
	if col := m.ta.LineInfo().ColumnOffset; col != 2 {
		t.Fatalf("expected cursor at col 2, got %d", col)
	}
}

func TestNoteEditorModifiedFlag(t *testing.T) {
	// Fresh note: clean until an edit happens.
	m := newNoteEditorModel("Note", "", "")
	if m.modified {
		t.Fatal("expected clean state initially")
	}
	m = sendNoteKeys(t, m, "x")
	if !m.modified {
		t.Fatal("expected modified after typing")
	}
	// Typing then undoing back to the initial state marks it clean again.
	m = sendNoteKeys(t, m, "ctrl+z")
	if m.modified {
		t.Fatal("expected clean after undoing back to initial")
	}
}

func TestNoteEditorInitialContentShowsAsClean(t *testing.T) {
	m := newNoteEditorModel("Note", "", "pre-existing")
	if m.modified {
		t.Fatal("existing content loaded from the vault should be clean")
	}
	m = sendNoteKeys(t, m, "!", "ctrl+s")
	if m.result != "pre-existing!" {
		t.Fatalf("expected appended content, got %q", m.result)
	}
}

func TestNoteEditorViewContainsChrome(t *testing.T) {
	m := newNoteEditorModel("Shopping List", "personal", "milk")
	m.width, m.height = 100, 30
	m.ta.SetWidth(noteEditorTextAreaWidth(100))
	m.ta.SetHeight(noteEditorTextAreaHeight(30, 100))
	view := m.View()
	for _, want := range []string{"APM NOTE EDITOR", "Shopping List", "space: personal", "Ln 1, Col", "milk", "^S save", "Esc cancel", "^U del-to-start", "alt+U/L/C word case"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected view to contain %q, got:\n%s", want, view)
		}
	}
}
