package apm

import (
	"os"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	os.Setenv("APM_SESSION_ID", "sessiontest")
	defer os.Unsetenv("APM_SESSION_ID")

	password := "testpassword"
	duration := 1 * time.Hour
	inactivity := 30 * time.Minute

	// Cleanup any stale session
	KillSession()

	// 1. Create Session
	err := CreateSession(password, duration, false, inactivity)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 2. Get Session
	sess, err := GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if sess.MasterPassword != password {
		t.Errorf("Expected password %s, got %s", password, sess.MasterPassword)
	}
	if sess.ReadOnly {
		t.Error("Expected ReadOnly to be false")
	}

	// 3. Kill Session
	err = KillSession()
	if err != nil {
		t.Fatalf("KillSession failed: %v", err)
	}

	// 4. Verify killed
	_, err = GetSession()
	if err == nil || err.Error() != "no active session" {
		t.Errorf("Expected 'no active session' error, got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	os.Setenv("APM_SESSION_ID", "expirytest")
	defer os.Unsetenv("APM_SESSION_ID")

	// Create a session that expires instantly (well, very soon)
	err := CreateSession("pass", 100*time.Millisecond, false, 0)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	_, err = GetSession()
	if err == nil || (err.Error() != "session expired" && err.Error() != "no active session") {
		t.Errorf("Expected 'session expired' (or already cleaned up), got %v", err)
	}
}

func TestSessionInactivity(t *testing.T) {
	os.Setenv("APM_SESSION_ID", "inactivitytest")
	defer os.Unsetenv("APM_SESSION_ID")

	// Create a session with short inactivity timeout
	err := CreateSession("pass", 1*time.Hour, false, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	_, err = GetSession()
	if err == nil || err.Error() != "session locked due to inactivity" {
		t.Errorf("Expected 'session locked due to inactivity' error, got %v", err)
	}
}
