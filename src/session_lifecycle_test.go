package apm

import (
	"fmt"
	"testing"
	"time"
)

func uniqueSessionID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestSessionLifecycle(t *testing.T) {
	t.Parallel()

	t.Setenv("APM_SESSION_ID", uniqueSessionID("lifecycle"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("testpassword", 2*time.Second, false, 1*time.Second); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	sess, err := GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess.MasterPassword != "testpassword" {
		t.Fatalf("unexpected password in session: %q", sess.MasterPassword)
	}
	if sess.ReadOnly {
		t.Fatal("expected ReadOnly=false")
	}

	if err := KillSession(); err != nil {
		t.Fatalf("KillSession failed: %v", err)
	}

	if _, err := GetSession(); err == nil || err.Error() != "no active session" {
		t.Fatalf("expected 'no active session', got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	t.Parallel()

	t.Setenv("APM_SESSION_ID", uniqueSessionID("expiry"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("pass", 100*time.Millisecond, false, 0); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(250 * time.Millisecond)

	_, err := GetSession()
	if err == nil {
		t.Fatal("expected expiry error")
	}
	if err.Error() != "session expired" && err.Error() != "no active session" {
		t.Fatalf("expected expiry-related error, got %v", err)
	}
}

func TestSessionInactivityLock(t *testing.T) {
	t.Parallel()

	t.Setenv("APM_SESSION_ID", uniqueSessionID("inactivity"))
	_ = KillSession()
	defer KillSession()

	if err := CreateSession("pass", 2*time.Second, false, 100*time.Millisecond); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	_, err := GetSession()
	if err == nil {
		t.Fatal("expected inactivity lock error")
	}
	if err.Error() != "session locked due to inactivity" && err.Error() != "no active session" {
		t.Fatalf("expected inactivity-related error, got %v", err)
	}
}
