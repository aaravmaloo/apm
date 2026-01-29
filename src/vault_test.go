package apm

import (
	"testing"
)

func FuzzDecryptVault(f *testing.F) {

	f.Add([]byte(VaultHeader+"\x00"), "password123")

	f.Add([]byte(VaultHeader), "password123")

	f.Add([]byte("notavaultatall"), "password123")

	f.Fuzz(func(t *testing.T, data []byte, password string) {

		_, _ = DecryptVault(data, password, 1)
	})
}
