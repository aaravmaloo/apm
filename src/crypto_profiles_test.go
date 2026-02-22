package apm

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateMasterPassword(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pass    string
		wantErr bool
	}{
		{name: "too-short", pass: "Aa1!", wantErr: true},
		{name: "missing-uppercase", pass: "lower123!", wantErr: true},
		{name: "missing-lowercase", pass: "UPPER123!", wantErr: true},
		{name: "missing-digit", pass: "ValidPass!", wantErr: true},
		{name: "missing-symbol", pass: "ValidPass123", wantErr: true},
		{name: "valid", pass: "ValidPass123!", wantErr: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMasterPassword(tc.pass)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for password %q", tc.pass)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for password %q: %v", tc.pass, err)
			}
		})
	}
}

func TestDeriveKeysDeterministicAndDistinct(t *testing.T) {
	t.Parallel()

	salt := []byte("0123456789abcdef")

	k1 := DeriveKeys("Password1!", salt, 1, 8*1024, 1)
	k2 := DeriveKeys("Password1!", salt, 1, 8*1024, 1)
	k3 := DeriveKeys("Different1!", salt, 1, 8*1024, 1)

	if len(k1.EncryptionKey) != 32 || len(k1.AuthKey) != 32 || len(k1.Validator) != 32 {
		t.Fatalf("unexpected key lengths: enc=%d auth=%d val=%d", len(k1.EncryptionKey), len(k1.AuthKey), len(k1.Validator))
	}

	if !bytes.Equal(k1.EncryptionKey, k2.EncryptionKey) {
		t.Fatal("expected deterministic encryption key for same input")
	}
	if !bytes.Equal(k1.AuthKey, k2.AuthKey) {
		t.Fatal("expected deterministic auth key for same input")
	}
	if !bytes.Equal(k1.Validator, k2.Validator) {
		t.Fatal("expected deterministic validator for same input")
	}

	if bytes.Equal(k1.EncryptionKey, k3.EncryptionKey) {
		t.Fatal("expected different encryption keys for different passwords")
	}
}

func TestHMACVerify(t *testing.T) {
	t.Parallel()

	data := []byte("payload")
	key := []byte("secret-key")

	sig := CalculateHMAC(data, key)
	if !VerifyHMAC(data, sig, key) {
		t.Fatal("expected valid HMAC verification")
	}

	tampered := []byte("payload-x")
	if VerifyHMAC(tampered, sig, key) {
		t.Fatal("expected HMAC verification to fail for tampered data")
	}
}

func TestRecommendProfileForSystem(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		info SystemProfileInfo
		want string
	}{
		{
			name: "high-end-system",
			info: SystemProfileInfo{CPUCores: 12, TotalMemoryMB: 32768, MemoryDetected: true},
			want: "paranoid",
		},
		{
			name: "mid-system",
			info: SystemProfileInfo{CPUCores: 6, TotalMemoryMB: 16384, MemoryDetected: true},
			want: "hardened",
		},
		{
			name: "low-system",
			info: SystemProfileInfo{CPUCores: 2, TotalMemoryMB: 4096, MemoryDetected: true},
			want: "standard",
		},
		{
			name: "no-memory-high-core",
			info: SystemProfileInfo{CPUCores: 8, MemoryDetected: false},
			want: "hardened",
		},
		{
			name: "no-memory-low-core",
			info: SystemProfileInfo{CPUCores: 4, MemoryDetected: false},
			want: "standard",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, reason := RecommendProfileForSystem(tc.info)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
			if strings.TrimSpace(reason) == "" {
				t.Fatal("expected non-empty recommendation reason")
			}
		})
	}
}
