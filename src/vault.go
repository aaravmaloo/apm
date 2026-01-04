package apm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

<<<<<<< Updated upstream
type Entry struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	Password string `json:"password"`
=======
type SSHKeyEntry struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

type WiFiEntry struct {
	SSID         string `json:"ssid"`
	Password     string `json:"password"`
	SecurityType string `json:"security_type"`
}

type RecoveryCodeEntry struct {
	Service string   `json:"service"`
	Codes   []string `json:"codes"`
}

type TokenEntry struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Token   string `json:"token"`
	Type    string `json:"type"`
>>>>>>> Stashed changes
}

func (v *Vault) Serialize(masterPassword string) ([]byte, error) {
	ciphertext, err := EncryptVault(v, masterPassword)
	if err != nil {
		return nil, err
	}

	return append(v.Salt, ciphertext...), nil
}

type TOTPEntry struct {
	Account string `json:"account"`
	Secret  string `json:"secret"`
}

<<<<<<< Updated upstream
=======
type HistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"` // "ADD", "UPDATE", "DELETE"
	Category   string    `json:"category"`
	Identifier string    `json:"identifier"`
	OldData    string    `json:"old_data,omitempty"`
}

type Entry struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	Password string `json:"password"`
}

>>>>>>> Stashed changes
type Vault struct {
	Salt        []byte      `json:"salt"`
	Entries     []Entry     `json:"entries"`
	TOTPEntries []TOTPEntry `json:"totp_entries"`
}

func EncryptVault(vault *Vault, masterPassword string) ([]byte, error) {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	key := DeriveKey(masterPassword, vault.Salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func DecryptVault(ciphertext []byte, masterPassword string, salt []byte) (*Vault, error) {
	key := DeriveKey(masterPassword, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: incorrect password or corrupted data")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}

	return &vault, nil
}

func EncryptData(plaintext []byte, password string) ([]byte, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return append(salt, ciphertext...), nil
}

func DecryptData(data []byte, password string) ([]byte, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid encrypted data: too short")
	}
	salt := data[:16]
	ciphertext := data[16:]

	key := DeriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: incorrect password or corrupted data")
	}

	return plaintext, nil
}

func (v *Vault) AddEntry(account, username, password string) {
	for i, entry := range v.Entries {
		if entry.Account == account {
			v.Entries[i] = Entry{Account: account, Username: username, Password: password}
			return
		}
	}
	v.Entries = append(v.Entries, Entry{Account: account, Username: username, Password: password})
}

func (v *Vault) GetEntry(account string) (Entry, bool) {
	for _, entry := range v.Entries {
		if entry.Account == account {
			return entry, true
		}
	}
	return Entry{}, false
}

func (v *Vault) DeleteEntry(account string) bool {
	for i, entry := range v.Entries {
		if entry.Account == account {
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			return true
		}
	}
	return false
}

func (v *Vault) AddTOTPEntry(account, secret string) {
	for i, entry := range v.TOTPEntries {
		if entry.Account == account {
			v.TOTPEntries[i] = TOTPEntry{Account: account, Secret: secret}
			return
		}
	}
	v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{Account: account, Secret: secret})
}

func (v *Vault) GetTOTPEntry(account string) (TOTPEntry, bool) {
	for _, entry := range v.TOTPEntries {
		if entry.Account == account {
			return entry, true
		}
	}
	return TOTPEntry{}, false
}

func (v *Vault) DeleteTOTPEntry(account string) bool {
	for i, entry := range v.TOTPEntries {
		if entry.Account == account {
			v.TOTPEntries = append(v.TOTPEntries[:i], v.TOTPEntries[i+1:]...)
			return true
		}
	}
	return false
}

func (v *Vault) SearchEntries(query string) []Entry {
	var results []Entry
	for _, entry := range v.Entries {
		if query == "" || fmt.Sprintf("%s %s", entry.Account, entry.Username) == query {
			results = append(results, entry)
		}
	}
	return results
}

func (v *Vault) FilterEntries(query string) []Entry {
	var results []Entry
	for _, entry := range v.Entries {
		if query == "" ||
			(contains(entry.Account, query) || contains(entry.Username, query)) {
			results = append(results, entry)
		}
	}
	return results
}

func contains(s, substr string) bool {

	return len(s) >= len(substr) && match(s, substr)
}

func match(s, substr string) bool {

	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
