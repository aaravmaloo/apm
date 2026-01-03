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

type Entry struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type SecureNoteEntry struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type APIKeyEntry struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Key     string `json:"key"`
}

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

type Vault struct {
	Salt              []byte              `json:"salt"`
	Entries           []Entry             `json:"entries"`
	TOTPEntries       []TOTPEntry         `json:"totp_entries"`
	SecureNotes       []SecureNoteEntry   `json:"secure_notes"`
	APIKeys           []APIKeyEntry       `json:"api_keys"`
	SSHKeys           []SSHKeyEntry       `json:"ssh_keys"`
	WiFiCredentials   []WiFiEntry         `json:"wifi_credentials"`
	RecoveryCodeItems []RecoveryCodeEntry `json:"recovery_codes"`
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

// Secure Notes
func (v *Vault) AddSecureNote(name, content string) {
	for i, entry := range v.SecureNotes {
		if entry.Name == name {
			v.SecureNotes[i] = SecureNoteEntry{Name: name, Content: content}
			return
		}
	}
	v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{Name: name, Content: content})
}

func (v *Vault) GetSecureNote(name string) (SecureNoteEntry, bool) {
	for _, entry := range v.SecureNotes {
		if entry.Name == name {
			return entry, true
		}
	}
	return SecureNoteEntry{}, false
}

func (v *Vault) DeleteSecureNote(name string) bool {
	for i, entry := range v.SecureNotes {
		if entry.Name == name {
			v.SecureNotes = append(v.SecureNotes[:i], v.SecureNotes[i+1:]...)
			return true
		}
	}
	return false
}

// API Keys
func (v *Vault) AddAPIKey(name, service, key string) {
	for i, entry := range v.APIKeys {
		if entry.Name == name {
			v.APIKeys[i] = APIKeyEntry{Name: name, Service: service, Key: key}
			return
		}
	}
	v.APIKeys = append(v.APIKeys, APIKeyEntry{Name: name, Service: service, Key: key})
}

func (v *Vault) GetAPIKey(name string) (APIKeyEntry, bool) {
	for _, entry := range v.APIKeys {
		if entry.Name == name {
			return entry, true
		}
	}
	return APIKeyEntry{}, false
}

func (v *Vault) DeleteAPIKey(name string) bool {
	for i, entry := range v.APIKeys {
		if entry.Name == name {
			v.APIKeys = append(v.APIKeys[:i], v.APIKeys[i+1:]...)
			return true
		}
	}
	return false
}

// SSH Keys
func (v *Vault) AddSSHKey(name, privateKey string) {
	for i, entry := range v.SSHKeys {
		if entry.Name == name {
			v.SSHKeys[i] = SSHKeyEntry{Name: name, PrivateKey: privateKey}
			return
		}
	}
	v.SSHKeys = append(v.SSHKeys, SSHKeyEntry{Name: name, PrivateKey: privateKey})
}

func (v *Vault) GetSSHKey(name string) (SSHKeyEntry, bool) {
	for _, entry := range v.SSHKeys {
		if entry.Name == name {
			return entry, true
		}
	}
	return SSHKeyEntry{}, false
}

func (v *Vault) DeleteSSHKey(name string) bool {
	for i, entry := range v.SSHKeys {
		if entry.Name == name {
			v.SSHKeys = append(v.SSHKeys[:i], v.SSHKeys[i+1:]...)
			return true
		}
	}
	return false
}

// Wi-Fi Credentials
func (v *Vault) AddWiFi(ssid, password, securityType string) {
	for i, entry := range v.WiFiCredentials {
		if entry.SSID == ssid {
			v.WiFiCredentials[i] = WiFiEntry{SSID: ssid, Password: password, SecurityType: securityType}
			return
		}
	}
	v.WiFiCredentials = append(v.WiFiCredentials, WiFiEntry{SSID: ssid, Password: password, SecurityType: securityType})
}

func (v *Vault) GetWiFi(ssid string) (WiFiEntry, bool) {
	for _, entry := range v.WiFiCredentials {
		if entry.SSID == ssid {
			return entry, true
		}
	}
	return WiFiEntry{}, false
}

func (v *Vault) DeleteWiFi(ssid string) bool {
	for i, entry := range v.WiFiCredentials {
		if entry.SSID == ssid {
			v.WiFiCredentials = append(v.WiFiCredentials[:i], v.WiFiCredentials[i+1:]...)
			return true
		}
	}
	return false
}

// Recovery Codes
func (v *Vault) AddRecoveryCode(service string, codes []string) {
	for i, entry := range v.RecoveryCodeItems {
		if entry.Service == service {
			v.RecoveryCodeItems[i] = RecoveryCodeEntry{Service: service, Codes: codes}
			return
		}
	}
	v.RecoveryCodeItems = append(v.RecoveryCodeItems, RecoveryCodeEntry{Service: service, Codes: codes})
}

func (v *Vault) GetRecoveryCode(service string) (RecoveryCodeEntry, bool) {
	for _, entry := range v.RecoveryCodeItems {
		if entry.Service == service {
			return entry, true
		}
	}
	return RecoveryCodeEntry{}, false
}

func (v *Vault) DeleteRecoveryCode(service string) bool {
	for i, entry := range v.RecoveryCodeItems {
		if entry.Service == service {
			v.RecoveryCodeItems = append(v.RecoveryCodeItems[:i], v.RecoveryCodeItems[i+1:]...)
			return true
		}
	}
	return false
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
