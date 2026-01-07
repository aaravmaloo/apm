package apm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	VaultHeader  = "APMVAULT"
	VaultVersion = 1
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

type TokenEntry struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Type  string `json:"type"` // e.g., "GitHub", "PyPI", etc.
}

type TOTPEntry struct {
	Account string `json:"account"`
	Secret  string `json:"secret"`
}

type HistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"` // "ADD", "UPDATE", "DELETE"
	Category   string    `json:"category"`
	Identifier string    `json:"identifier"`
	OldData    string    `json:"old_data,omitempty"` // JSON string of the previous state
}

type Vault struct {
	// Salt is removed from struct as it is now part of the file header
	Entries           []Entry             `json:"entries"`
	TOTPEntries       []TOTPEntry         `json:"totp_entries"`
	Tokens            []TokenEntry        `json:"tokens"`
	SecureNotes       []SecureNoteEntry   `json:"secure_notes"`
	APIKeys           []APIKeyEntry       `json:"api_keys"`
	SSHKeys           []SSHKeyEntry       `json:"ssh_keys"`
	WiFiCredentials   []WiFiEntry         `json:"wifi_credentials"`
	RecoveryCodeItems []RecoveryCodeEntry `json:"recovery_codes"`
	History           []HistoryEntry      `json:"history"`
}

func (v *Vault) Serialize(masterPassword string) ([]byte, error) {
	return EncryptVault(v, masterPassword)
}

// EncryptVault encrypts the vault with the new secure format:
// Header (8) | Version (1) | Salt (16) | Validator (32) | IV (12) | Ciphertext (...) | HMAC (32)
// Total Header Overhead: 8 + 1 + 16 + 32 + 12 = 69 bytes
// Trailer: 32 bytes (HMAC)
func EncryptVault(vault *Vault, masterPassword string) ([]byte, error) {
	// 1. Prepare JSON
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	// 2. Generate Salt & Derive Keys
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}
	keys := DeriveKeys(masterPassword, salt)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	// 3. Encrypt
	block, err := aes.NewCipher(keys.EncryptionKey)
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
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// 4. Construct Payload for HMAC
	// Payload = Header + Version + Salt + Validator + IV + Ciphertext
	var buffer bytes.Buffer
	buffer.WriteString(VaultHeader)
	buffer.WriteByte(VaultVersion)
	buffer.Write(salt)
	buffer.Write(keys.Validator)
	buffer.Write(nonce)
	buffer.Write(ciphertext)

	payload := buffer.Bytes()

	// 5. Calculate HMAC (Tamper Detection)
	mac := CalculateHMAC(payload, keys.AuthKey)

	// 6. Final Output: Payload + HMAC
	return append(payload, mac...), nil
}

// DecryptVault decrypts the vault table handling both new and old formats
func DecryptVault(data []byte, masterPassword string) (*Vault, error) {
	// Check for magic header to detect new format
	if len(data) > len(VaultHeader) && string(data[:len(VaultHeader)]) == VaultHeader {
		return decryptNewVault(data, masterPassword)
	}
	// Fallback to old format
	return decryptOldVault(data, masterPassword)
}

func decryptNewVault(data []byte, masterPassword string) (*Vault, error) {
	minLen := len(VaultHeader) + 1 + SaltSize + ValidatorSize + NonceSize + 32 // + HMAC(32)
	if len(data) < minLen {
		return nil, errors.New("corrupted file: too short")
	}

	// Parse pieces
	offset := 0

	// Header
	header := string(data[offset : offset+len(VaultHeader)])
	offset += len(VaultHeader)
	if header != VaultHeader {
		return nil, errors.New("invalid file header")
	}

	// Version
	version := data[offset]
	offset += 1
	if version != VaultVersion {
		return nil, fmt.Errorf("unsupported vault version: %d", version)
	}

	// Salt
	salt := data[offset : offset+SaltSize]
	offset += SaltSize

	// Validator
	storedValidator := data[offset : offset+ValidatorSize]
	offset += ValidatorSize

	// Derive Keys
	keys := DeriveKeys(masterPassword, salt)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	// Verify Password (Constant Time)
	// If this fails, it is definitely a "Wrong Password" error
	if !VerifyPasswordValidator(keys.Validator, storedValidator) {
		return nil, errors.New("wrong password")
	}

	// Split HMAC from the end
	macOffset := len(data) - 32
	payload := data[:macOffset]
	storedHMAC := data[macOffset:]

	// Verify HMAC (Tamper Detection)
	if !VerifyHMAC(payload, storedHMAC, keys.AuthKey) {
		return nil, errors.New("tampered file: integrity check failed")
	}

	// Extract IV and Ciphertext for decryption
	nonce := data[offset : offset+NonceSize]
	offset += NonceSize
	ciphertext := data[offset:macOffset]

	// Decrypt
	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}
	return &vault, nil
}

// decryptOldVault handles the legacy JSON format
func decryptOldVault(data []byte, masterPassword string) (*Vault, error) {
	// Old format: [Salt (16)] [IV (12) + Ciphertext + Tag]
	if len(data) < 16+12 {
		return nil, errors.New("invalid legacy data")
	}

	salt := data[:16]
	ciphertext := data[16:]

	// Legacy key derivation: Argon2id, Time=1, Mem=256MB, Parallelism=4, KeyLen=32
	key := argon2.IDKey([]byte(masterPassword), salt, 1, 256*1024, 4, 32)

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
		return nil, errors.New("legacy ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, errors.New("legacy decryption failed: wrong password or corrupted data")
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
	keys := DeriveKeys(password, salt)
	defer Wipe(keys.EncryptionKey)

	block, err := aes.NewCipher(keys.EncryptionKey)
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
		return nil, errors.New("invalid data")
	}
	salt := data[:16]
	ciphertext := data[16:]

	keys := DeriveKeys(password, salt)
	defer Wipe(keys.EncryptionKey)

	block, err := aes.NewCipher(keys.EncryptionKey)
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
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (v *Vault) EntryExistsWithOtherType(name, currentType string) bool {
	for _, e := range v.Entries {
		if e.Account == name && currentType != "PASSWORD" {
			return true
		}
	}
	for _, t := range v.TOTPEntries {
		if t.Account == name && currentType != "TOTP" {
			return true
		}
	}
	for _, tok := range v.Tokens {
		if tok.Name == name && currentType != "TOKEN" {
			return true
		}
	}
	for _, n := range v.SecureNotes {
		if n.Name == name && currentType != "NOTE" {
			return true
		}
	}
	for _, k := range v.APIKeys {
		if k.Name == name && currentType != "API_KEY" {
			return true
		}
	}
	for _, s := range v.SSHKeys {
		if s.Name == name && currentType != "SSH_KEY" {
			return true
		}
	}
	for _, w := range v.WiFiCredentials {
		if w.SSID == name && currentType != "WIFI" {
			return true
		}
	}
	for _, r := range v.RecoveryCodeItems {
		if r.Service == name && currentType != "RECOVERY_CODE" {
			return true
		}
	}
	return false
}

func (v *Vault) AddEntry(account, username, password string) error {
	if v.EntryExistsWithOtherType(account, "PASSWORD") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", account)
	}
	for i, entry := range v.Entries {
		if entry.Account == account {
			oldData, _ := json.Marshal(v.Entries[i])
			v.Entries[i] = Entry{Account: account, Username: username, Password: password}
			v.logHistory("UPDATE", "PASSWORD", account, string(oldData))
			return nil
		}
	}
	v.Entries = append(v.Entries, Entry{Account: account, Username: username, Password: password})
	v.logHistory("ADD", "PASSWORD", account, "")
	return nil
}

func (v *Vault) logHistory(action, category, identifier, oldData string) {
	v.History = append(v.History, HistoryEntry{
		Timestamp:  time.Now(),
		Action:     action,
		Category:   category,
		Identifier: identifier,
		OldData:    oldData,
	})
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
			oldData, _ := json.Marshal(v.Entries[i])
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			v.logHistory("DELETE", "PASSWORD", account, string(oldData))
			return true
		}
	}
	return false
}

func (v *Vault) AddTOTPEntry(account, secret string) error {
	if v.EntryExistsWithOtherType(account, "TOTP") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", account)
	}
	for i, entry := range v.TOTPEntries {
		if entry.Account == account {
			oldData, _ := json.Marshal(v.TOTPEntries[i])
			v.TOTPEntries[i] = TOTPEntry{Account: account, Secret: secret}
			v.logHistory("UPDATE", "TOTP", account, string(oldData))
			return nil
		}
	}
	v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{Account: account, Secret: secret})
	v.logHistory("ADD", "TOTP", account, "")
	return nil
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
			oldData, _ := json.Marshal(v.TOTPEntries[i])
			v.TOTPEntries = append(v.TOTPEntries[:i], v.TOTPEntries[i+1:]...)
			v.logHistory("DELETE", "TOTP", account, string(oldData))
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
func (v *Vault) AddSecureNote(name, content string) error {
	if v.EntryExistsWithOtherType(name, "NOTE") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", name)
	}
	for i, entry := range v.SecureNotes {
		if entry.Name == name {
			oldData, _ := json.Marshal(v.SecureNotes[i])
			v.SecureNotes[i] = SecureNoteEntry{Name: name, Content: content}
			v.logHistory("UPDATE", "NOTE", name, string(oldData))
			return nil
		}
	}
	v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{Name: name, Content: content})
	v.logHistory("ADD", "NOTE", name, "")
	return nil
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
			oldData, _ := json.Marshal(v.SecureNotes[i])
			v.SecureNotes = append(v.SecureNotes[:i], v.SecureNotes[i+1:]...)
			v.logHistory("DELETE", "NOTE", name, string(oldData))
			return true
		}
	}
	return false
}

// API Keys
func (v *Vault) AddAPIKey(name, service, key string) error {
	if v.EntryExistsWithOtherType(name, "API_KEY") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", name)
	}
	for i, entry := range v.APIKeys {
		if entry.Name == name {
			oldData, _ := json.Marshal(v.APIKeys[i])
			v.APIKeys[i] = APIKeyEntry{Name: name, Service: service, Key: key}
			v.logHistory("UPDATE", "API_KEY", name, string(oldData))
			return nil
		}
	}
	v.APIKeys = append(v.APIKeys, APIKeyEntry{Name: name, Service: service, Key: key})
	v.logHistory("ADD", "API_KEY", name, "")
	return nil
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
			oldData, _ := json.Marshal(v.APIKeys[i])
			v.APIKeys = append(v.APIKeys[:i], v.APIKeys[i+1:]...)
			v.logHistory("DELETE", "API_KEY", name, string(oldData))
			return true
		}
	}
	return false
}

// SSH Keys
func (v *Vault) AddSSHKey(name, privateKey string) error {
	if v.EntryExistsWithOtherType(name, "SSH_KEY") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", name)
	}
	for i, entry := range v.SSHKeys {
		if entry.Name == name {
			oldData, _ := json.Marshal(v.SSHKeys[i])
			v.SSHKeys[i] = SSHKeyEntry{Name: name, PrivateKey: privateKey}
			v.logHistory("UPDATE", "SSH_KEY", name, string(oldData))
			return nil
		}
	}
	v.SSHKeys = append(v.SSHKeys, SSHKeyEntry{Name: name, PrivateKey: privateKey})
	v.logHistory("ADD", "SSH_KEY", name, "")
	return nil
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
			oldData, _ := json.Marshal(v.SSHKeys[i])
			v.SSHKeys = append(v.SSHKeys[:i], v.SSHKeys[i+1:]...)
			v.logHistory("DELETE", "SSH_KEY", name, string(oldData))
			return true
		}
	}
	return false
}

// Wi-Fi Credentials
func (v *Vault) AddWiFi(ssid, password, securityType string) error {
	if v.EntryExistsWithOtherType(ssid, "WIFI") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", ssid)
	}
	for i, entry := range v.WiFiCredentials {
		if entry.SSID == ssid {
			oldData, _ := json.Marshal(v.WiFiCredentials[i])
			v.WiFiCredentials[i] = WiFiEntry{SSID: ssid, Password: password, SecurityType: securityType}
			v.logHistory("UPDATE", "WIFI", ssid, string(oldData))
			return nil
		}
	}
	v.WiFiCredentials = append(v.WiFiCredentials, WiFiEntry{SSID: ssid, Password: password, SecurityType: securityType})
	v.logHistory("ADD", "WIFI", ssid, "")
	return nil
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
			oldData, _ := json.Marshal(v.WiFiCredentials[i])
			v.WiFiCredentials = append(v.WiFiCredentials[:i], v.WiFiCredentials[i+1:]...)
			v.logHistory("DELETE", "WIFI", ssid, string(oldData))
			return true
		}
	}
	return false
}

// Recovery Codes
func (v *Vault) AddRecoveryCode(service string, codes []string) error {
	if v.EntryExistsWithOtherType(service, "RECOVERY_CODE") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", service)
	}
	for i, entry := range v.RecoveryCodeItems {
		if entry.Service == service {
			oldData, _ := json.Marshal(v.RecoveryCodeItems[i])
			v.RecoveryCodeItems[i] = RecoveryCodeEntry{Service: service, Codes: codes}
			v.logHistory("UPDATE", "RECOVERY_CODE", service, string(oldData))
			return nil
		}
	}
	v.RecoveryCodeItems = append(v.RecoveryCodeItems, RecoveryCodeEntry{Service: service, Codes: codes})
	v.logHistory("ADD", "RECOVERY_CODE", service, "")
	return nil
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
			oldData, _ := json.Marshal(v.RecoveryCodeItems[i])
			v.RecoveryCodeItems = append(v.RecoveryCodeItems[:i], v.RecoveryCodeItems[i+1:]...)
			v.logHistory("DELETE", "RECOVERY_CODE", service, string(oldData))
			return true
		}
	}
	return false
}

// Tokens
func (v *Vault) AddToken(name, token, tokenType string) error {
	if v.EntryExistsWithOtherType(name, "TOKEN") {
		return fmt.Errorf("an entry with the name '%s' already exists in another category", name)
	}
	for i, entry := range v.Tokens {
		if entry.Name == name {
			oldData, _ := json.Marshal(v.Tokens[i])
			v.Tokens[i] = TokenEntry{Name: name, Token: token, Type: tokenType}
			v.logHistory("UPDATE", "TOKEN", name, string(oldData))
			return nil
		}
	}
	v.Tokens = append(v.Tokens, TokenEntry{Name: name, Token: token, Type: tokenType})
	v.logHistory("ADD", "TOKEN", name, "")
	return nil
}

func (v *Vault) GetToken(name string) (TokenEntry, bool) {
	for _, entry := range v.Tokens {
		if entry.Name == name {
			return entry, true
		}
	}
	return TokenEntry{}, false
}

func (v *Vault) DeleteToken(name string) bool {
	for i, entry := range v.Tokens {
		if entry.Name == name {
			oldData, _ := json.Marshal(v.Tokens[i])
			v.Tokens = append(v.Tokens[:i], v.Tokens[i+1:]...)
			v.logHistory("DELETE", "TOKEN", name, string(oldData))
			return true
		}
	}
	return false
}

func (v *Vault) SearchAll(query string) []SearchResult {
	var results []SearchResult
	query = strings.ToLower(query)

	for _, e := range v.Entries {
		if query == "" || strings.Contains(strings.ToLower(e.Account), query) || strings.Contains(strings.ToLower(e.Username), query) {
			results = append(results, SearchResult{Type: "Password", Identifier: e.Account, Data: e})
		}
	}
	for _, t := range v.TOTPEntries {
		if query == "" || strings.Contains(strings.ToLower(t.Account), query) {
			results = append(results, SearchResult{Type: "TOTP", Identifier: t.Account, Data: t})
		}
	}
	for _, tok := range v.Tokens {
		if query == "" || strings.Contains(strings.ToLower(tok.Name), query) {
			results = append(results, SearchResult{Type: "Token", Identifier: tok.Name, Data: tok})
		}
	}
	for _, n := range v.SecureNotes {
		if query == "" || strings.Contains(strings.ToLower(n.Name), query) {
			results = append(results, SearchResult{Type: "Note", Identifier: n.Name, Data: n})
		}
	}
	for _, k := range v.APIKeys {
		if query == "" || strings.Contains(strings.ToLower(k.Name), query) || strings.Contains(strings.ToLower(k.Service), query) {
			results = append(results, SearchResult{Type: "API Key", Identifier: k.Name, Data: k})
		}
	}
	for _, s := range v.SSHKeys {
		if query == "" || strings.Contains(strings.ToLower(s.Name), query) {
			results = append(results, SearchResult{Type: "SSH Key", Identifier: s.Name, Data: s})
		}
	}
	for _, w := range v.WiFiCredentials {
		if query == "" || strings.Contains(strings.ToLower(w.SSID), query) {
			results = append(results, SearchResult{Type: "Wi-Fi", Identifier: w.SSID, Data: w})
		}
	}
	for _, r := range v.RecoveryCodeItems {
		if query == "" || strings.Contains(strings.ToLower(r.Service), query) {
			results = append(results, SearchResult{Type: "Recovery Codes", Identifier: r.Service, Data: r})
		}
	}

	return results
}

type SearchResult struct {
	Type       string
	Identifier string
	Data       interface{}
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
