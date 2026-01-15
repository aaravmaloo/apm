package apm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const VaultHeader = "APMVAULT"

const CurrentVersion = 3

func GetVaultParams(data []byte) (CryptoProfile, int, error) {
	if len(data) < len(VaultHeader) || string(data[:len(VaultHeader)]) != VaultHeader {
		return CryptoProfile{}, 0, errors.New("invalid vault header")
	}
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	if version == 1 {
		return ProfileStandard, 1, nil
	} else if version == 2 {
		if offset >= len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		name := string(data[offset : offset+nameLen])
		return GetProfile(name), 2, nil
	} else if version == 3 {
		if offset+2 > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		pLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		if offset+pLen > len(data) {
			return CryptoProfile{}, 0, errors.New("short header")
		}
		var p CryptoProfile
		if err := json.Unmarshal(data[offset:offset+pLen], &p); err != nil {
			return CryptoProfile{}, 0, err
		}
		return p, 3, nil
	}
	return CryptoProfile{}, 0, fmt.Errorf("unknown version %d", version)
}

type Entry struct {
	Account  string `json:"account"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type TOTPEntry struct {
	Account string `json:"account"`
	Secret  string `json:"secret"`
}

type TokenEntry struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Type  string `json:"type"`
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

type HistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Category   string    `json:"category"`
	Identifier string    `json:"identifier"`
}

type CertificateEntry struct {
	Label      string    `json:"label"`
	CertData   string    `json:"cert_data"`
	PrivateKey string    `json:"private_key"`
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
}

type BankingEntry struct {
	Label    string `json:"label"`
	Type     string `json:"type"`
	Details  string `json:"details"`
	CVV      string `json:"cvv,omitempty"`
	Expiry   string `json:"expiry,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
}

type DocumentEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Password string `json:"password"`
}

type Vault struct {
	Salt                    []byte              `json:"salt"`
	Entries                 []Entry             `json:"entries"`
	TOTPEntries             []TOTPEntry         `json:"totp_entries"`
	Tokens                  []TokenEntry        `json:"tokens"`
	SecureNotes             []SecureNoteEntry   `json:"secure_notes"`
	APIKeys                 []APIKeyEntry       `json:"api_keys"`
	SSHKeys                 []SSHKeyEntry       `json:"ssh_keys"`
	WiFiCredentials         []WiFiEntry         `json:"wifi_credentials"`
	RecoveryCodeItems       []RecoveryCodeEntry `json:"recovery_codes"`
	Certificates            []CertificateEntry  `json:"certificates"`
	BankingItems            []BankingEntry      `json:"banking_items"`
	Documents               []DocumentEntry     `json:"documents"`
	History                 []HistoryEntry      `json:"history"`
	RetrievalKey            string              `json:"retrieval_key,omitempty"`
	CloudFileID             string              `json:"cloud_file_id,omitempty"`
	CloudCredentials        []byte              `json:"cloud_credentials,omitempty"`
	CloudToken              []byte              `json:"cloud_token,omitempty"`
	FailedAttempts          uint8               `json:"failed_attempts,omitempty"`
	EmergencyMode           bool                `json:"emergency_mode,omitempty"`
	Profile                 string              `json:"profile,omitempty"`
	AlertEmail              string              `json:"alert_email,omitempty"`
	AlertsEnabled           bool                `json:"alerts_enabled,omitempty"`
	AnomalyDetectionEnabled bool                `json:"anomaly_detection_enabled,omitempty"`

	CurrentProfileParams *CryptoProfile `json:"-"`
}

func (v *Vault) Serialize(masterPassword string) ([]byte, error) {
	return EncryptVault(v, masterPassword)
}

func EncryptVault(vault *Vault, masterPassword string) ([]byte, error) {
	var profile CryptoProfile
	if vault.CurrentProfileParams != nil {
		profile = *vault.CurrentProfileParams
		if profile.Name == "" {
			profile.Name = "custom"
		}
	} else {
		if vault.Profile == "" {
			vault.Profile = "standard"
		}
		profile = GetProfile(vault.Profile)
	}

	salt, err := GenerateSalt(profile.SaltLen)
	if err != nil {
		return nil, err
	}

	keys := DeriveKeys(masterPassword, salt, profile.Time, profile.Memory, profile.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	jsonData, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, profile.NonceLen)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, jsonData, nil)

	var payload []byte
	payload = append(payload, []byte(VaultHeader)...)
	payload = append(payload, byte(CurrentVersion))

	encProfile, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	if len(encProfile) > 65535 {
		return nil, errors.New("profile data too large")
	}
	lenBytes := make([]byte, 2)
	lenBytes[0] = byte(len(encProfile) >> 8)
	lenBytes[1] = byte(len(encProfile))
	payload = append(payload, lenBytes...)
	payload = append(payload, encProfile...)

	payload = append(payload, salt...)
	payload = append(payload, keys.Validator...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	signature := CalculateHMAC(payload, keys.AuthKey)
	finalData := append(payload, signature...)

	return finalData, nil
}

func DecryptVault(data []byte, masterPassword string, costMultiplier int) (*Vault, error) {
	if len(data) > len(VaultHeader) && string(data[:len(VaultHeader)]) == VaultHeader {
		return decryptNewVault(data, masterPassword, costMultiplier)
	}
	if len(data) < 16 {
		return nil, errors.New("invalid vault data")
	}
	salt := data[:16]
	ciphertext := data[16:]
	return decryptOldVault(ciphertext, masterPassword, salt)
}

func decryptNewVault(data []byte, masterPassword string, costMultiplier int) (*Vault, error) {
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	var profile CryptoProfile

	if version == 1 {
		time := uint32(3)
		mem := uint32(128 * 1024)
		if costMultiplier > 1 {
			time *= uint32(costMultiplier)
			mem *= uint32(costMultiplier)
		}
		profile = CryptoProfile{
			Name: "legacy_v1", KDF: "argon2id", Time: time, Memory: mem, Parallelism: 4, SaltLen: 16, NonceLen: 12,
		}
	} else if version == 2 {
		if offset >= len(data) {
			return nil, errors.New("corrupted header")
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen > len(data) {
			return nil, errors.New("corrupted header (profile name)")
		}
		profileName := string(data[offset : offset+nameLen])
		offset += nameLen
		profile = GetProfile(profileName)
	} else if version == 3 {
		if offset+2 > len(data) {
			return nil, errors.New("corrupted header (params len)")
		}
		pLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+pLen > len(data) {
			return nil, errors.New("corrupted header (params)")
		}
		pBytes := data[offset : offset+pLen]
		offset += pLen

		if err := json.Unmarshal(pBytes, &profile); err != nil {
			return nil, fmt.Errorf("corrupted profile data: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unsupported vault version: %d", version)
	}

	if offset+profile.SaltLen > len(data) {
		return nil, errors.New("corrupted header (salt)")
	}
	salt := data[offset : offset+profile.SaltLen]
	offset += profile.SaltLen

	if offset+32 > len(data) {
		return nil, errors.New("corrupted header (validator)")
	}
	storedValidator := data[offset : offset+32]
	offset += 32

	if offset+profile.NonceLen > len(data) {
		return nil, errors.New("corrupted header (nonce)")
	}
	nonce := data[offset : offset+profile.NonceLen]
	offset += profile.NonceLen

	rest := data[offset:]
	if len(rest) < 32 {
		return nil, errors.New("vault file corrupted (missing HMAC)")
	}
	ciphertext := rest[:len(rest)-32]
	storedHMAC := rest[len(rest)-32:]

	keys := DeriveKeys(masterPassword, salt, profile.Time, profile.Memory, profile.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	if !VerifyPasswordValidator(keys.Validator, storedValidator) {
		return nil, errors.New("incorrect password")
	}

	payloadForHMAC := data[:len(data)-32]
	if !VerifyHMAC(payloadForHMAC, storedHMAC, keys.AuthKey) {
		return nil, errors.New("vault file has been tampered with or corrupted")
	}

	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, profile.NonceLen)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed despite valid password")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}
	vault.CurrentProfileParams = &profile
	return &vault, nil
}

func decryptOldVault(ciphertext []byte, masterPassword string, salt []byte) (*Vault, error) {
	key := DeriveLegacyKey(masterPassword, salt)
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
	salt, err := GenerateSalt(16)
	if err != nil {
		return nil, err
	}
	p := ProfileStandard
	keys := DeriveKeys(password, salt, p.Time, p.Memory, p.Parallelism)
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
	if len(data) < 16+12 {
		return nil, errors.New("data too short")
	}
	salt := data[:16]
	ciphertext := data[16:]

	keys := DeriveKeys(password, salt, ProfileStandard.Time, ProfileStandard.Memory, ProfileStandard.Parallelism)
	block, err := aes.NewCipher(keys.EncryptionKey)
	if err == nil {
		gcm, err := cipher.NewGCM(block)
		if err == nil {
			nonceSize := gcm.NonceSize()
			if len(ciphertext) >= nonceSize {
				nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
				plaintext, err := gcm.Open(nil, nonce, ct, nil)
				if err == nil {
					return plaintext, nil
				}
			}
		}
	}
	legacyKey := DeriveLegacyKey(password, salt)
	block, err = aes.NewCipher(legacyKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}

func (v *Vault) logHistory(action, category, identifier string) {
	v.History = append(v.History, HistoryEntry{
		Timestamp:  time.Now(),
		Action:     action,
		Category:   category,
		Identifier: identifier,
	})
}

func (v *Vault) AddEntry(account, username, password string) error {
	for _, e := range v.Entries {
		if e.Account == account {
			return errors.New("account already exists")
		}
	}
	v.Entries = append(v.Entries, Entry{Account: account, Username: username, Password: password})
	v.logHistory("ADD", "PASSWORD", account)
	return nil
}

func (v *Vault) GetEntry(account string) (Entry, bool) {
	for _, e := range v.Entries {
		if e.Account == account {
			return e, true
		}
	}
	return Entry{}, false
}

func (v *Vault) DeleteEntry(account string) bool {
	for i, e := range v.Entries {
		if e.Account == account {
			v.Entries = append(v.Entries[:i], v.Entries[i+1:]...)
			v.logHistory("DEL", "PASSWORD", account)
			return true
		}
	}
	return false
}

func (v *Vault) AddTOTPEntry(account, secret string) error {
	for _, e := range v.TOTPEntries {
		if e.Account == account {
			return errors.New("TOTP account already exists")
		}
	}
	v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{Account: account, Secret: secret})
	v.logHistory("ADD", "TOTP", account)
	return nil
}

func (v *Vault) GetTOTPEntry(account string) (TOTPEntry, bool) {
	for _, e := range v.TOTPEntries {
		if e.Account == account {
			return e, true
		}
	}
	return TOTPEntry{}, false
}

func (v *Vault) DeleteTOTPEntry(account string) bool {
	for i, e := range v.TOTPEntries {
		if e.Account == account {
			v.TOTPEntries = append(v.TOTPEntries[:i], v.TOTPEntries[i+1:]...)
			v.logHistory("DEL", "TOTP", account)
			return true
		}
	}
	return false
}

func (v *Vault) AddToken(name, token, tType string) error {
	for _, e := range v.Tokens {
		if e.Name == name {
			return errors.New("token already exists")
		}
	}
	v.Tokens = append(v.Tokens, TokenEntry{Name: name, Token: token, Type: tType})
	v.logHistory("ADD", "TOKEN", name)
	return nil
}

func (v *Vault) GetToken(name string) (TokenEntry, bool) {
	for _, e := range v.Tokens {
		if e.Name == name {
			return e, true
		}
	}
	return TokenEntry{}, false
}

func (v *Vault) DeleteToken(name string) bool {
	for i, e := range v.Tokens {
		if e.Name == name {
			v.Tokens = append(v.Tokens[:i], v.Tokens[i+1:]...)
			v.logHistory("DEL", "TOKEN", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSecureNote(name, content string) error {
	for _, e := range v.SecureNotes {
		if e.Name == name {
			return errors.New("note already exists")
		}
	}
	v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{Name: name, Content: content})
	v.logHistory("ADD", "NOTE", name)
	return nil
}

func (v *Vault) GetSecureNote(name string) (SecureNoteEntry, bool) {
	for _, e := range v.SecureNotes {
		if e.Name == name {
			return e, true
		}
	}
	return SecureNoteEntry{}, false
}

func (v *Vault) DeleteSecureNote(name string) bool {
	for i, e := range v.SecureNotes {
		if e.Name == name {
			v.SecureNotes = append(v.SecureNotes[:i], v.SecureNotes[i+1:]...)
			v.logHistory("DEL", "NOTE", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddAPIKey(name, service, key string) error {
	for _, e := range v.APIKeys {
		if e.Name == name {
			return errors.New("API key already exists")
		}
	}
	v.APIKeys = append(v.APIKeys, APIKeyEntry{Name: name, Service: service, Key: key})
	v.logHistory("ADD", "APIKEY", name)
	return nil
}

func (v *Vault) GetAPIKey(name string) (APIKeyEntry, bool) {
	for _, e := range v.APIKeys {
		if e.Name == name {
			return e, true
		}
	}
	return APIKeyEntry{}, false
}

func (v *Vault) DeleteAPIKey(name string) bool {
	for i, e := range v.APIKeys {
		if e.Name == name {
			v.APIKeys = append(v.APIKeys[:i], v.APIKeys[i+1:]...)
			v.logHistory("DEL", "APIKEY", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSSHKey(name, privateKey string) error {
	for _, e := range v.SSHKeys {
		if e.Name == name {
			return errors.New("SSH key already exists")
		}
	}
	v.SSHKeys = append(v.SSHKeys, SSHKeyEntry{Name: name, PrivateKey: privateKey})
	v.logHistory("ADD", "SSHKEY", name)
	return nil
}

func (v *Vault) GetSSHKey(name string) (SSHKeyEntry, bool) {
	for _, e := range v.SSHKeys {
		if e.Name == name {
			return e, true
		}
	}
	return SSHKeyEntry{}, false
}

func (v *Vault) DeleteSSHKey(name string) bool {
	for i, e := range v.SSHKeys {
		if e.Name == name {
			v.SSHKeys = append(v.SSHKeys[:i], v.SSHKeys[i+1:]...)
			v.logHistory("DEL", "SSHKEY", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddWiFi(ssid, password, security string) error {
	for _, e := range v.WiFiCredentials {
		if e.SSID == ssid {
			return errors.New("WiFi already exists")
		}
	}
	v.WiFiCredentials = append(v.WiFiCredentials, WiFiEntry{SSID: ssid, Password: password, SecurityType: security})
	v.logHistory("ADD", "WIFI", ssid)
	return nil
}

func (v *Vault) GetWiFi(ssid string) (WiFiEntry, bool) {
	for _, e := range v.WiFiCredentials {
		if e.SSID == ssid {
			return e, true
		}
	}
	return WiFiEntry{}, false
}

func (v *Vault) DeleteWiFi(ssid string) bool {
	for i, e := range v.WiFiCredentials {
		if e.SSID == ssid {
			v.WiFiCredentials = append(v.WiFiCredentials[:i], v.WiFiCredentials[i+1:]...)
			v.logHistory("DEL", "WIFI", ssid)
			return true
		}
	}
	return false
}

func (v *Vault) AddRecoveryCode(service string, codes []string) error {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service {
			return errors.New("recovery codes for service already exist")
		}
	}
	v.RecoveryCodeItems = append(v.RecoveryCodeItems, RecoveryCodeEntry{Service: service, Codes: codes})
	v.logHistory("ADD", "RECOVERY", service)
	return nil
}

func (v *Vault) GetRecoveryCode(service string) (RecoveryCodeEntry, bool) {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service {
			return e, true
		}
	}
	return RecoveryCodeEntry{}, false
}

func (v *Vault) DeleteRecoveryCode(service string) bool {
	for i, e := range v.RecoveryCodeItems {
		if e.Service == service {
			v.RecoveryCodeItems = append(v.RecoveryCodeItems[:i], v.RecoveryCodeItems[i+1:]...)
			v.logHistory("DEL", "RECOVERY", service)
			return true
		}
	}
	return false
}

func (v *Vault) AddCertificate(label, cert, key, issuer string, expiry time.Time) error {
	for _, e := range v.Certificates {
		if e.Label == label {
			return errors.New("certificate already exists")
		}
	}
	v.Certificates = append(v.Certificates, CertificateEntry{Label: label, CertData: cert, PrivateKey: key, Issuer: issuer, Expiry: expiry})
	v.logHistory("ADD", "CERTIFICATE", label)
	return nil
}

func (v *Vault) GetCertificate(label string) (CertificateEntry, bool) {
	for _, e := range v.Certificates {
		if e.Label == label {
			return e, true
		}
	}
	return CertificateEntry{}, false
}

func (v *Vault) DeleteCertificate(label string) bool {
	for i, e := range v.Certificates {
		if e.Label == label {
			v.Certificates = append(v.Certificates[:i], v.Certificates[i+1:]...)
			v.logHistory("DEL", "CERTIFICATE", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddBankingItem(label, bType, details, cvv, expiry string) error {
	for _, e := range v.BankingItems {
		if e.Label == label {
			return errors.New("banking item already exists")
		}
	}
	v.BankingItems = append(v.BankingItems, BankingEntry{Label: label, Type: bType, Details: details, CVV: cvv, Expiry: expiry})
	v.logHistory("ADD", "BANKING", label)
	return nil
}

func (v *Vault) GetBankingItem(label string) (BankingEntry, bool) {
	for _, e := range v.BankingItems {
		if e.Label == label {
			return e, true
		}
	}
	return BankingEntry{}, false
}

func (v *Vault) DeleteBankingItem(label string) bool {
	for i, e := range v.BankingItems {
		if e.Label == label {
			v.BankingItems = append(v.BankingItems[:i], v.BankingItems[i+1:]...)
			v.logHistory("DEL", "BANKING", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddDocument(name, fileName string, content []byte, password string) error {
	for _, e := range v.Documents {
		if e.Name == name {
			return errors.New("document already exists")
		}
	}
	v.Documents = append(v.Documents, DocumentEntry{Name: name, FileName: fileName, Content: content, Password: password})
	v.logHistory("ADD", "DOCUMENT", name)
	return nil
}

func (v *Vault) GetDocument(name string) (DocumentEntry, bool) {
	for _, e := range v.Documents {
		if e.Name == name {
			return e, true
		}
	}
	return DocumentEntry{}, false
}

func (v *Vault) DeleteDocument(name string) bool {
	for i, e := range v.Documents {
		if e.Name == name {
			v.Documents = append(v.Documents[:i], v.Documents[i+1:]...)
			v.logHistory("DEL", "DOCUMENT", name)
			return true
		}
	}
	return false
}

type SearchResult struct {
	Type       string
	Identifier string
	Data       interface{}
}

func (v *Vault) SearchAll(query string) []SearchResult {
	var results []SearchResult
	query = strings.ToLower(query)

	for _, e := range v.Entries {
		if query == "" || strings.Contains(strings.ToLower(e.Account), query) {
			results = append(results, SearchResult{"Password", e.Account, e})
		}
	}
	for _, e := range v.TOTPEntries {
		if query == "" || strings.Contains(strings.ToLower(e.Account), query) {
			results = append(results, SearchResult{"TOTP", e.Account, e})
		}
	}
	for _, e := range v.Tokens {
		if query == "" || strings.Contains(strings.ToLower(e.Name), query) {
			results = append(results, SearchResult{"Token", e.Name, e})
		}
	}
	for _, e := range v.SecureNotes {
		if query == "" || strings.Contains(strings.ToLower(e.Name), query) {
			results = append(results, SearchResult{"Note", e.Name, e})
		}
	}
	for _, e := range v.APIKeys {
		if query == "" || strings.Contains(strings.ToLower(e.Name), query) {
			results = append(results, SearchResult{"API Key", e.Name, e})
		}
	}
	for _, e := range v.SSHKeys {
		if query == "" || strings.Contains(strings.ToLower(e.Name), query) {
			results = append(results, SearchResult{"SSH Key", e.Name, e})
		}
	}
	for _, e := range v.WiFiCredentials {
		if query == "" || strings.Contains(strings.ToLower(e.SSID), query) {
			results = append(results, SearchResult{"Wi-Fi", e.SSID, e})
		}
	}
	for _, e := range v.RecoveryCodeItems {
		if query == "" || strings.Contains(strings.ToLower(e.Service), query) {
			results = append(results, SearchResult{"Recovery Codes", e.Service, e})
		}
	}
	for _, e := range v.Certificates {
		if query == "" || strings.Contains(strings.ToLower(e.Label), query) {
			results = append(results, SearchResult{"Certificate", e.Label, e})
		}
	}
	for _, e := range v.BankingItems {
		if query == "" || strings.Contains(strings.ToLower(e.Label), query) {
			results = append(results, SearchResult{"Banking", e.Label, e})
		}
	}
	for _, e := range v.Documents {
		if query == "" || strings.Contains(strings.ToLower(e.Name), query) {
			results = append(results, SearchResult{"Document", e.Name, e})
		}
	}
	return results
}
