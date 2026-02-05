package apm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const VaultHeader = "APMVAULT"

const CurrentVersion = 4

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
	Space    string `json:"space,omitempty"`
}

type TOTPEntry struct {
	Account string `json:"account"`
	Secret  string `json:"secret"`
	Space   string `json:"space,omitempty"`
}

type TokenEntry struct {
	Name  string `json:"name"`
	Token string `json:"token"`
	Type  string `json:"type"`
	Space string `json:"space,omitempty"`
}

type SecureNoteEntry struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Space   string `json:"space,omitempty"`
}

type APIKeyEntry struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Key     string `json:"key"`
	Space   string `json:"space,omitempty"`
}

type SSHKeyEntry struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	Space      string `json:"space,omitempty"`
}

type WiFiEntry struct {
	SSID         string `json:"ssid"`
	Password     string `json:"password"`
	SecurityType string `json:"security_type"`
	RouterIP     string `json:"router_ip"`
	Space        string `json:"space,omitempty"`
}

type GovIDEntry struct {
	Type     string `json:"type"`
	IDNumber string `json:"id_number"`
	Name     string `json:"name"`
	Expiry   string `json:"expiry"`
	Space    string `json:"space,omitempty"`
}

type MedicalRecordEntry struct {
	Label         string `json:"label"`
	InsuranceID   string `json:"insurance_id"`
	Prescriptions string `json:"prescriptions"`
	Allergies     string `json:"allergies"`
	Space         string `json:"space,omitempty"`
}

type TravelEntry struct {
	Label          string `json:"label"`
	TicketNumber   string `json:"ticket_number"`
	BookingCode    string `json:"booking_code"`
	LoyaltyProgram string `json:"loyalty_program"`
	Space          string `json:"Space,omitempty"`
}

type ContactEntry struct {
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Email     string `json:"email"`
	Address   string `json:"address"`
	Emergency bool   `json:"emergency"`
	Space     string `json:"space,omitempty"`
}

type CloudCredentialEntry struct {
	Label      string `json:"label"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
	Region     string `json:"region"`
	AccountID  string `json:"account_id"`
	Role       string `json:"role"`
	Expiration string `json:"expiration"`
	Space      string `json:"space,omitempty"`
}

type K8sSecretEntry struct {
	Name         string `json:"name"`
	ClusterURL   string `json:"cluster_url"`
	K8sNamespace string `json:"namespace"`
	Expiration   string `json:"expiration"`
	Space        string `json:"space,omitempty"`
}

type DockerRegistryEntry struct {
	Name        string `json:"name"`
	RegistryURL string `json:"registry_url"`
	Username    string `json:"username"`
	Token       string `json:"token"`
	Space       string `json:"Space,omitempty"`
}

type SSHConfigEntry struct {
	Alias       string `json:"alias"`
	Host        string `json:"host"`
	User        string `json:"user"`
	Port        string `json:"port"`
	KeyPath     string `json:"key_path"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	Space       string `json:"Space,omitempty"`
}

type CICDSecretEntry struct {
	Name    string `json:"name"`
	Webhook string `json:"webhook"`
	EnvVars string `json:"env_vars"`
	Space   string `json:"space,omitempty"`
}

type SoftwareLicenseEntry struct {
	ProductName    string `json:"product_name"`
	SerialKey      string `json:"serial_key"`
	ActivationInfo string `json:"activation_info"`
	Expiration     string `json:"expiration"`
	Space          string `json:"Space,omitempty"`
}

type LegalContractEntry struct {
	Name            string `json:"name"`
	Summary         string `json:"summary"`
	PartiesInvolved string `json:"parties_involved"`
	SignedDate      string `json:"signed_date"`
	Space           string `json:"space,omitempty"`
}

type RecoveryCodeEntry struct {
	Service string   `json:"service"`
	Codes   []string `json:"codes"`
	Space   string   `json:"space,omitempty"`
}

type HistoryEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	Category   string    `json:"category"`
	Identifier string    `json:"identifier"`
	Hash       string    `json:"hash,omitempty"`
	Signature  string    `json:"signature,omitempty"`
}

type CertificateEntry struct {
	Label      string    `json:"label"`
	CertData   string    `json:"cert_data"`
	PrivateKey string    `json:"private_key"`
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
	Space      string    `json:"space,omitempty"`
}

type BankingEntry struct {
	Label    string `json:"label"`
	Type     string `json:"type"`
	Details  string `json:"details"`
	CVV      string `json:"cvv,omitempty"`
	Expiry   string `json:"expiry,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
	Space    string `json:"space,omitempty"`
}

type DocumentEntry struct {
	Name     string   `json:"name"`
	FileName string   `json:"file_name"`
	Content  []byte   `json:"content"`
	Password string   `json:"password"`
	Tags     []string `json:"tags,omitempty"`
	Expiry   string   `json:"expiry,omitempty"`
	Space    string   `json:"space,omitempty"`
}

type RecoveryData struct {
	EmailHash     []byte `json:"email_hash,omitempty"`
	KeyHash       []byte `json:"key_hash,omitempty"`
	DEKSlot       []byte `json:"dek_slot,omitempty"` // DEK encrypted with Recovery Key
	ObfuscatedKey []byte `json:"obfuscated_key,omitempty"`
}

type AudioEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type VideoEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type PhotoEntry struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Space    string `json:"space,omitempty"`
}

type Vault struct {
	Salt                    []byte                 `json:"salt"`
	Entries                 []Entry                `json:"entries"`
	TOTPEntries             []TOTPEntry            `json:"totp_entries"`
	Tokens                  []TokenEntry           `json:"tokens"`
	SecureNotes             []SecureNoteEntry      `json:"secure_notes"`
	APIKeys                 []APIKeyEntry          `json:"api_keys"`
	SSHKeys                 []SSHKeyEntry          `json:"ssh_keys"`
	WiFiCredentials         []WiFiEntry            `json:"wifi_credentials"`
	RecoveryCodeItems       []RecoveryCodeEntry    `json:"recovery_codes"`
	Certificates            []CertificateEntry     `json:"certificates"`
	BankingItems            []BankingEntry         `json:"banking_items"`
	Documents               []DocumentEntry        `json:"documents"`
	AudioFiles              []AudioEntry           `json:"audio_files"`
	VideoFiles              []VideoEntry           `json:"video_files"`
	PhotoFiles              []PhotoEntry           `json:"photo_files"`
	GovIDs                  []GovIDEntry           `json:"gov_ids"`
	MedicalRecords          []MedicalRecordEntry   `json:"medical_records"`
	TravelDocs              []TravelEntry          `json:"travel_docs"`
	Contacts                []ContactEntry         `json:"contacts"`
	CloudCredentialsItems   []CloudCredentialEntry `json:"cloud_credentials_items"`
	K8sSecrets              []K8sSecretEntry       `json:"k8s_secrets"`
	DockerRegistries        []DockerRegistryEntry  `json:"docker_registries"`
	SSHConfigs              []SSHConfigEntry       `json:"ssh_configs"`
	CICDSecrets             []CICDSecretEntry      `json:"cicd_secrets"`
	SoftwareLicenses        []SoftwareLicenseEntry `json:"software_licenses"`
	LegalContracts          []LegalContractEntry   `json:"legal_contracts"`
	History                 []HistoryEntry         `json:"history"`
	RetrievalKey            string                 `json:"retrieval_key,omitempty"`
	CloudFileID             string                 `json:"cloud_file_id,omitempty"`
	CloudCredentials        []byte                 `json:"cloud_credentials,omitempty"`
	CloudToken              []byte                 `json:"cloud_token,omitempty"`
	FailedAttempts          uint8                  `json:"failed_attempts,omitempty"`
	EmergencyMode           bool                   `json:"emergency_mode,omitempty"`
	Profile                 string                 `json:"profile,omitempty"`
	AlertEmail              string                 `json:"alert_email,omitempty"`
	AlertsEnabled           bool                   `json:"alerts_enabled,omitempty"`
	AnomalyDetectionEnabled bool                   `json:"anomaly_detection_enabled,omitempty"`
	LastCloudProvider       string                 `json:"last_cloud_provider,omitempty"`
	DriveSyncMode           string                 `json:"drive_sync_mode,omitempty"` // "apm_public" or "self_hosted"
	GitHubToken             string                 `json:"github_token,omitempty"`
	GitHubRepo              string                 `json:"github_repo,omitempty"`
	CurrentSpace            string                 `json:"current_space,omitempty"`
	Spaces                  []string               `json:"spaces"`
	ActivePolicy            Policy                 `json:"active_policy,omitempty"`

	CurrentProfileParams *CryptoProfile `json:"-"`
	RecoveryEmail        string         `json:"recovery_email,omitempty"`
	RecoveryHash         []byte         `json:"recovery_hash,omitempty"`
	DEK                  []byte         `json:"dek,omitempty"`
	RecoverySlot         []byte         `json:"recovery_slot,omitempty"`
	RawRecoveryKey       string         `json:"-"`
	ObfuscatedKey        []byte         `json:"-"`
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

	// In V4, we ensure a DEK exists. If not, generate one.
	if len(vault.DEK) == 0 {
		vault.DEK = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, vault.DEK); err != nil {
			return nil, err
		}
	}

	jsonData, err := json.Marshal(vault)
	if err != nil {
		return nil, err
	}

	// Encrypt jsonData with DEK
	dekBlock, err := aes.NewCipher(vault.DEK)
	if err != nil {
		return nil, err
	}
	dekGcm, err := cipher.NewGCMWithNonceSize(dekBlock, profile.NonceLen)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, dekGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := dekGcm.Seal(nil, nonce, jsonData, nil)

	var payload []byte
	payload = append(payload, []byte(VaultHeader)...)
	payload = append(payload, byte(CurrentVersion))

	// Profile Params
	encProfile, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	lenBytes := make([]byte, 2)
	lenBytes[0] = byte(len(encProfile) >> 8)
	lenBytes[1] = byte(len(encProfile))
	payload = append(payload, lenBytes...)
	payload = append(payload, encProfile...)

	// V4: Recovery Metadata (Unencrypted for verification)
	var rec RecoveryData
	if vault.RecoveryEmail != "" {
		h := sha256.Sum256([]byte(strings.ToLower(vault.RecoveryEmail)))
		rec.EmailHash = h[:]
	}

	if len(vault.RecoverySlot) > 0 {
		rec.DEKSlot = vault.RecoverySlot
		rec.KeyHash = vault.RecoveryHash
	}

	if vault.RawRecoveryKey != "" {
		rec.ObfuscatedKey = XORRecoveryKey(vault.RawRecoveryKey)
	} else if len(vault.ObfuscatedKey) > 0 {
		rec.ObfuscatedKey = vault.ObfuscatedKey
	}

	encRec, _ := json.Marshal(rec)
	recLenBytes := make([]byte, 2)
	recLenBytes[0] = byte(len(encRec) >> 8)
	recLenBytes[1] = byte(len(encRec))
	payload = append(payload, recLenBytes...)
	payload = append(payload, encRec...)

	payload = append(payload, salt...)
	payload = append(payload, keys.Validator...)
	payload = append(payload, nonce...)

	// Master Slot: Encrypt DEK with MasterPassword-derived key
	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, err
	}
	masterSlotGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	mNonce := make([]byte, masterSlotGcm.NonceSize())
	masterSlot := masterSlotGcm.Seal(nil, mNonce, vault.DEK, nil)
	payload = append(payload, masterSlot...)

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
	} else if version == 3 || version == 4 {
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

		if version == 4 {
			if offset+2 > len(data) {
				return nil, errors.New("corrupted header (recovery len)")
			}
			rLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2 + rLen
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

	keys := DeriveKeys(masterPassword, salt, profile.Time, profile.Memory, profile.Parallelism)
	defer Wipe(keys.EncryptionKey)
	defer Wipe(keys.AuthKey)
	defer Wipe(keys.Validator)

	if !VerifyPasswordValidator(keys.Validator, storedValidator) {
		return nil, errors.New("incorrect password")
	}

	payloadForHMAC := data[:len(data)-32]
	storedHMAC := data[len(data)-32:]
	if !VerifyHMAC(payloadForHMAC, storedHMAC, keys.AuthKey) {
		return nil, errors.New("vault file has been tampered with or corrupted")
	}

	var dek []byte
	if version == 4 {
		// Decrypt Master Slot
		masterSlotLen := 32 + 16 // DEK(32) + GCM tag(16)
		if offset+masterSlotLen > len(data)-32 {
			return nil, errors.New("corrupted master slot")
		}
		masterSlot := data[offset : offset+masterSlotLen]
		offset += masterSlotLen

		block, _ := aes.NewCipher(keys.EncryptionKey)
		gcm, _ := cipher.NewGCM(block)
		mNonce := make([]byte, gcm.NonceSize())
		var err error
		dek, err = gcm.Open(nil, mNonce, masterSlot, nil)
		if err != nil {
			return nil, errors.New("failed to decrypt master slot")
		}
	} else {
		dek = keys.EncryptionKey
	}

	ciphertext := data[offset : len(data)-32]

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGcm, err := cipher.NewGCMWithNonceSize(dekBlock, profile.NonceLen)
	if err != nil {
		return nil, err
	}

	plaintext, err := dekGcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}
	if version == 4 {
		rec, _ := GetVaultRecoveryInfo(data)
		vault.ObfuscatedKey = rec.ObfuscatedKey
	}
	vault.CurrentProfileParams = &profile
	return &vault, nil
}

func DecryptVaultWithDEK(data []byte, dek []byte) (*Vault, error) {
	offset := len(VaultHeader)
	version := data[offset]
	offset++

	if version != 4 {
		return nil, errors.New("direct DEK decryption only supported for V4")
	}

	// Skip Profile
	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + pLen
	// Skip RecoveryData
	rLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + rLen
	// Skip Salt
	offset += 16
	// Skip Validator
	offset += 32

	// Read Nonce
	nonceLen := 12
	nonce := data[offset : offset+nonceLen]
	offset += nonceLen

	// Skip Master Slot
	offset += 32 + 16

	ciphertext := data[offset : len(data)-32]

	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCMWithNonceSize(block, nonceLen)

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var vault Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, err
	}

	if version == 4 {
		rec, _ := GetVaultRecoveryInfo(data)
		vault.ObfuscatedKey = rec.ObfuscatedKey
	}
	return &vault, nil
}

func UpdateMasterPassword(v *Vault, oldPass, newPass string) ([]byte, error) {
	return EncryptVault(v, newPass)
}

func GetVaultRecoveryInfo(data []byte) (RecoveryData, error) {
	if len(data) < len(VaultHeader)+1 {
		return RecoveryData{}, errors.New("invalid vault")
	}
	offset := len(VaultHeader)
	version := data[offset]
	offset++
	if version != 4 {
		return RecoveryData{}, errors.New("vault version does not support recovery")
	}

	// Skip Profile
	if offset+2 > len(data) {
		return RecoveryData{}, errors.New("corrupted header")
	}
	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + pLen

	if offset+2 > len(data) {
		return RecoveryData{}, errors.New("corrupted header")
	}
	rLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+rLen > len(data) {
		return RecoveryData{}, errors.New("corrupted header")
	}
	var rec RecoveryData
	if err := json.Unmarshal(data[offset:offset+rLen], &rec); err != nil {
		return RecoveryData{}, err
	}
	return rec, nil
}

func (v *Vault) SetRecoveryEmail(email string) {
	v.RecoveryEmail = email
}

func (v *Vault) ClearRecoveryInfo() {
	v.RecoveryEmail = ""
	v.RecoveryHash = nil
	v.RecoverySlot = nil
	v.RawRecoveryKey = ""
	v.ObfuscatedKey = nil
}

func GenerateRecoveryKey() string {
	chars := "ABCDEFGHJKLMNPQRSTUVWXYZ"
	nums := "23456789"

	gen := func(pool string, length int) string {
		res := make([]byte, length)
		for i := 0; i < length; i++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
			res[i] = pool[n.Int64()]
		}
		return string(res)
	}

	// LNLN-LNLN-LLLL-NNNN
	part1 := string([]byte{gen(chars, 1)[0], gen(nums, 1)[0], gen(chars, 1)[0], gen(nums, 1)[0]})
	part2 := string([]byte{gen(chars, 1)[0], gen(nums, 1)[0], gen(chars, 1)[0], gen(nums, 1)[0]})
	part3 := gen(chars, 4)
	part4 := gen(nums, 4)

	return fmt.Sprintf("%s-%s-%s-%s", part1, part2, part3, part4)
}

func DeriveRecoveryKey(key string, salt []byte) []byte {
	// Simple KDF for recovery key to secret
	hash := sha256.New()
	hash.Write([]byte(key))
	hash.Write(salt)
	return hash.Sum(nil)
}

func (v *Vault) SetRecoveryKey(key string, salt []byte) {
	v.RawRecoveryKey = key
	rk := DeriveRecoveryKey(key, salt)

	// Create KeyHash for verification
	h := sha256.Sum256(rk)
	v.RecoveryHash = h[:]

	// Encrypt DEK with RK to create RecoverySlot
	block, _ := aes.NewCipher(rk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	// Use zero nonce for deterministic recovery slot
	v.RecoverySlot = gcm.Seal(nil, nonce, v.DEK, nil)
}

func XORRecoveryKey(key string) []byte {
	// Simple XOR obfuscation with a fixed key
	xorKey := []byte("APM_RECOVERY_OBFUSCATION_SALT_2026")
	data := []byte(key)
	res := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		res[i] = data[i] ^ xorKey[i%len(xorKey)]
	}
	return res
}

func DeObfuscateRecoveryKey(obf []byte) string {
	xorKey := []byte("APM_RECOVERY_OBFUSCATION_SALT_2026")
	res := make([]byte, len(obf))
	for i := 0; i < len(obf); i++ {
		res[i] = obf[i] ^ xorKey[i%len(xorKey)]
	}
	return string(res)
}

func CheckRecoveryKey(data []byte, key string) ([]byte, error) {
	rec, err := GetVaultRecoveryInfo(data)
	if err != nil {
		return nil, err
	}
	if len(rec.KeyHash) == 0 || len(rec.DEKSlot) == 0 {
		return nil, errors.New("no recovery setup found in vault")
	}

	// Read salt from header to re-derive key
	offset := len(VaultHeader) + 1 // Header + Version
	// Skip Profile
	if offset+2 > len(data) {
		return nil, errors.New("corrupted header")
	}
	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + pLen
	// Skip RecoveryData
	if offset+2 > len(data) {
		return nil, errors.New("corrupted header")
	}
	rLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + rLen

	saltLen := 16 // Default
	if offset+saltLen > len(data) {
		return nil, errors.New("corrupted header (salt)")
	}
	salt := data[offset : offset+saltLen]

	rk := DeriveRecoveryKey(key, salt)
	h := sha256.Sum256(rk)

	if !hmac.Equal(h[:], rec.KeyHash) {
		return nil, errors.New("invalid recovery key")
	}

	// Decrypt DEK
	block, err := aes.NewCipher(rk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	dek, err := gcm.Open(nil, nonce, rec.DEKSlot, nil)
	if err != nil {
		return nil, errors.New("failed to decrypt recovery slot")
	}
	return dek, nil
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
	entry := HistoryEntry{
		Timestamp:  time.Now(),
		Action:     action,
		Category:   category,
		Identifier: identifier,
	}

	// Calculate Hash: SHA256(Timestamp + Action + Category + Identifier)
	// Using generic formatting for timestamp to ensure consistency
	data := fmt.Sprintf("%d:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Category, entry.Identifier)
	hash := sha256.Sum256([]byte(data))
	entry.Hash = hex.EncodeToString(hash[:])

	// Calculate Signature: HMAC-SHA256(Hash, VaultSalt)
	// We use the Vault's Salt as the key for simplicity in this implementation.
	// ideally we would derive a specific Audit Key, but Salt is persistent enough.
	mac := hmac.New(sha256.New, v.Salt)
	mac.Write([]byte(entry.Hash))
	entry.Signature = hex.EncodeToString(mac.Sum(nil))

	v.History = append(v.History, entry)
}

func (v *Vault) AddEntry(account, username, password string) error {
	if v.ActivePolicy.PasswordPolicy.MinLength > 0 {
		if err := v.ActivePolicy.PasswordPolicy.Validate(password); err != nil {
			return err
		}
	}
	for _, e := range v.Entries {
		if e.Account == account && e.Space == v.CurrentSpace {
			return errors.New("account already exists in this space")
		}
	}
	v.Entries = append(v.Entries, Entry{Account: account, Username: username, Password: password, Space: v.CurrentSpace})
	v.logHistory("ADD", "PASSWORD", account)
	return nil
}

func (v *Vault) GetEntry(account string) (Entry, bool) {
	for _, e := range v.Entries {
		if e.Account == account && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.Account == account && e.Space == v.CurrentSpace {
			return errors.New("TOTP account already exists in this space")
		}
	}
	v.TOTPEntries = append(v.TOTPEntries, TOTPEntry{Account: account, Secret: secret, Space: v.CurrentSpace})
	v.logHistory("ADD", "TOTP", account)
	return nil
}

func (v *Vault) GetTOTPEntry(account string) (TOTPEntry, bool) {
	for _, e := range v.TOTPEntries {
		if e.Account == account && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("token already exists in this space")
		}
	}
	v.Tokens = append(v.Tokens, TokenEntry{Name: name, Token: token, Type: tType, Space: v.CurrentSpace})
	v.logHistory("ADD", "TOKEN", name)
	return nil
}

func (v *Vault) GetToken(name string) (TokenEntry, bool) {
	for _, e := range v.Tokens {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("note already exists in this space")
		}
	}
	v.SecureNotes = append(v.SecureNotes, SecureNoteEntry{Name: name, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "NOTE", name)
	return nil
}

func (v *Vault) GetSecureNote(name string) (SecureNoteEntry, bool) {
	for _, e := range v.SecureNotes {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("API key already exists in this space")
		}
	}
	v.APIKeys = append(v.APIKeys, APIKeyEntry{Name: name, Service: service, Key: key, Space: v.CurrentSpace})
	v.logHistory("ADD", "APIKEY", name)
	return nil
}

func (v *Vault) GetAPIKey(name string) (APIKeyEntry, bool) {
	for _, e := range v.APIKeys {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("SSH key already exists in this space")
		}
	}
	v.SSHKeys = append(v.SSHKeys, SSHKeyEntry{Name: name, PrivateKey: privateKey, Space: v.CurrentSpace})
	v.logHistory("ADD", "SSHKEY", name)
	return nil
}

func (v *Vault) GetSSHKey(name string) (SSHKeyEntry, bool) {
	for _, e := range v.SSHKeys {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
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
		if e.SSID == ssid && e.Space == v.CurrentSpace {
			return errors.New("WiFi already exists in this space")
		}
	}
	v.WiFiCredentials = append(v.WiFiCredentials, WiFiEntry{SSID: ssid, Password: password, SecurityType: security, Space: v.CurrentSpace})
	v.logHistory("ADD", "WIFI", ssid)
	return nil
}

func (v *Vault) GetWiFi(ssid string) (WiFiEntry, bool) {
	for _, e := range v.WiFiCredentials {
		if e.SSID == ssid && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return WiFiEntry{}, false
}

func (v *Vault) DeleteWiFi(ssid string) bool {
	for i, e := range v.WiFiCredentials {
		if e.SSID == ssid && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.WiFiCredentials = append(v.WiFiCredentials[:i], v.WiFiCredentials[i+1:]...)
			v.logHistory("DEL", "WIFI", ssid)
			return true
		}
	}
	return false
}

func (v *Vault) AddRecoveryCode(service string, codes []string) error {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service && e.Space == v.CurrentSpace {
			return errors.New("recovery codes for service already exist in this space")
		}
	}
	v.RecoveryCodeItems = append(v.RecoveryCodeItems, RecoveryCodeEntry{Service: service, Codes: codes, Space: v.CurrentSpace})
	v.logHistory("ADD", "RECOVERY", service)
	return nil
}

func (v *Vault) GetRecoveryCode(service string) (RecoveryCodeEntry, bool) {
	for _, e := range v.RecoveryCodeItems {
		if e.Service == service && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return RecoveryCodeEntry{}, false
}

func (v *Vault) DeleteRecoveryCode(service string) bool {
	for i, e := range v.RecoveryCodeItems {
		if e.Service == service && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.RecoveryCodeItems = append(v.RecoveryCodeItems[:i], v.RecoveryCodeItems[i+1:]...)
			v.logHistory("DEL", "RECOVERY", service)
			return true
		}
	}
	return false
}

func (v *Vault) AddCertificate(label, cert, key, issuer string, expiry time.Time) error {
	for _, e := range v.Certificates {
		if e.Label == label && e.Space == v.CurrentSpace {
			return errors.New("certificate already exists in this space")
		}
	}
	v.Certificates = append(v.Certificates, CertificateEntry{Label: label, CertData: cert, PrivateKey: key, Issuer: issuer, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "CERTIFICATE", label)
	return nil
}

func (v *Vault) GetCertificate(label string) (CertificateEntry, bool) {
	for _, e := range v.Certificates {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return CertificateEntry{}, false
}

func (v *Vault) DeleteCertificate(label string) bool {
	for i, e := range v.Certificates {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Certificates = append(v.Certificates[:i], v.Certificates[i+1:]...)
			v.logHistory("DEL", "CERTIFICATE", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddBankingItem(label, bType, details, cvv, expiry string) error {
	for _, e := range v.BankingItems {
		if e.Label == label && e.Space == v.CurrentSpace {
			return errors.New("banking item already exists in this space")
		}
	}
	v.BankingItems = append(v.BankingItems, BankingEntry{Label: label, Type: bType, Details: details, CVV: cvv, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "BANKING", label)
	return nil
}

func (v *Vault) GetBankingItem(label string) (BankingEntry, bool) {
	for _, e := range v.BankingItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return BankingEntry{}, false
}

func (v *Vault) DeleteBankingItem(label string) bool {
	for i, e := range v.BankingItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.BankingItems = append(v.BankingItems[:i], v.BankingItems[i+1:]...)
			v.logHistory("DEL", "BANKING", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddDocument(name, fileName string, content []byte, password string, tags []string, expiry string) error {
	for _, e := range v.Documents {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("document already exists in this space")
		}
	}
	v.Documents = append(v.Documents, DocumentEntry{Name: name, FileName: fileName, Content: content, Password: password, Tags: tags, Expiry: expiry, Space: v.CurrentSpace})
	v.logHistory("ADD", "DOCUMENT", name)
	return nil
}

func (v *Vault) GetDocument(name string) (DocumentEntry, bool) {
	for _, e := range v.Documents {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return DocumentEntry{}, false
}

func (v *Vault) DeleteDocument(name string) bool {
	for i, e := range v.Documents {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Documents = append(v.Documents[:i], v.Documents[i+1:]...)
			v.logHistory("DEL", "DOCUMENT", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddAudio(name, fileName string, content []byte) error {
	for _, e := range v.AudioFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("audio file already exists in this space")
		}
	}
	v.AudioFiles = append(v.AudioFiles, AudioEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "AUDIO", name)
	return nil
}

func (v *Vault) GetAudio(name string) (AudioEntry, bool) {
	for _, e := range v.AudioFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return AudioEntry{}, false
}

func (v *Vault) DeleteAudio(name string) bool {
	for i, e := range v.AudioFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.AudioFiles = append(v.AudioFiles[:i], v.AudioFiles[i+1:]...)
			v.logHistory("DEL", "AUDIO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddVideo(name, fileName string, content []byte) error {
	for _, e := range v.VideoFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("video file already exists in this space")
		}
	}
	v.VideoFiles = append(v.VideoFiles, VideoEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "VIDEO", name)
	return nil
}

func (v *Vault) GetVideo(name string) (VideoEntry, bool) {
	for _, e := range v.VideoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return VideoEntry{}, false
}

func (v *Vault) DeleteVideo(name string) bool {
	for i, e := range v.VideoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.VideoFiles = append(v.VideoFiles[:i], v.VideoFiles[i+1:]...)
			v.logHistory("DEL", "VIDEO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddPhoto(name, fileName string, content []byte) error {
	for _, e := range v.PhotoFiles {
		if e.Name == name && e.Space == v.CurrentSpace {
			return errors.New("photo file already exists in this space")
		}
	}
	v.PhotoFiles = append(v.PhotoFiles, PhotoEntry{Name: name, FileName: fileName, Content: content, Space: v.CurrentSpace})
	v.logHistory("ADD", "PHOTO", name)
	return nil
}

func (v *Vault) GetPhoto(name string) (PhotoEntry, bool) {
	for _, e := range v.PhotoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			return e, true
		}
	}
	return PhotoEntry{}, false
}

func (v *Vault) DeletePhoto(name string) bool {
	for i, e := range v.PhotoFiles {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.PhotoFiles = append(v.PhotoFiles[:i], v.PhotoFiles[i+1:]...)
			v.logHistory("DEL", "PHOTO", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddGovID(g GovIDEntry) error {
	for _, e := range v.GovIDs {
		if e.IDNumber == g.IDNumber && e.Type == g.Type && e.Space == v.CurrentSpace {
			return errors.New("government ID already exists in this space")
		}
	}
	g.Space = v.CurrentSpace
	v.GovIDs = append(v.GovIDs, g)
	v.logHistory("ADD", "GOVID", g.IDNumber)
	return nil
}

func (v *Vault) DeleteGovID(idNum string) bool {
	for i, e := range v.GovIDs {
		if e.IDNumber == idNum && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.GovIDs = append(v.GovIDs[:i], v.GovIDs[i+1:]...)
			v.logHistory("DEL", "GOVID", idNum)
			return true
		}
	}
	return false
}

func (v *Vault) AddMedicalRecord(m MedicalRecordEntry) error {
	m.Space = v.CurrentSpace
	v.MedicalRecords = append(v.MedicalRecords, m)
	v.logHistory("ADD", "MEDICAL", m.Label)
	return nil
}

func (v *Vault) DeleteMedicalRecord(label string) bool {
	for i, e := range v.MedicalRecords {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.MedicalRecords = append(v.MedicalRecords[:i], v.MedicalRecords[i+1:]...)
			v.logHistory("DEL", "MEDICAL", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddTravelDoc(t TravelEntry) error {
	t.Space = v.CurrentSpace
	v.TravelDocs = append(v.TravelDocs, t)
	v.logHistory("ADD", "TRAVEL", t.Label)
	return nil
}

func (v *Vault) DeleteTravelDoc(label string) bool {
	for i, e := range v.TravelDocs {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.TravelDocs = append(v.TravelDocs[:i], v.TravelDocs[i+1:]...)
			v.logHistory("DEL", "TRAVEL", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddContact(c ContactEntry) error {
	c.Space = v.CurrentSpace
	v.Contacts = append(v.Contacts, c)
	v.logHistory("ADD", "CONTACT", c.Name)
	return nil
}

func (v *Vault) DeleteContact(name string) bool {
	for i, e := range v.Contacts {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.Contacts = append(v.Contacts[:i], v.Contacts[i+1:]...)
			v.logHistory("DEL", "CONTACT", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddCloudCredential(c CloudCredentialEntry) error {
	c.Space = v.CurrentSpace
	v.CloudCredentialsItems = append(v.CloudCredentialsItems, c)
	v.logHistory("ADD", "CLOUDCRED", c.Label)
	return nil
}

func (v *Vault) DeleteCloudCredential(label string) bool {
	for i, e := range v.CloudCredentialsItems {
		if e.Label == label && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.CloudCredentialsItems = append(v.CloudCredentialsItems[:i], v.CloudCredentialsItems[i+1:]...)
			v.logHistory("DEL", "CLOUDCRED", label)
			return true
		}
	}
	return false
}

func (v *Vault) AddK8sSecret(k K8sSecretEntry) error {
	k.Space = v.CurrentSpace
	v.K8sSecrets = append(v.K8sSecrets, k)
	v.logHistory("ADD", "K8S", k.Name)
	return nil
}

func (v *Vault) DeleteK8sSecret(name string) bool {
	for i, e := range v.K8sSecrets {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.K8sSecrets = append(v.K8sSecrets[:i], v.K8sSecrets[i+1:]...)
			v.logHistory("DEL", "K8S", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddDockerRegistry(d DockerRegistryEntry) error {
	d.Space = v.CurrentSpace
	v.DockerRegistries = append(v.DockerRegistries, d)
	v.logHistory("ADD", "DOCKER", d.Name)
	return nil
}

func (v *Vault) DeleteDockerRegistry(name string) bool {
	for i, e := range v.DockerRegistries {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.DockerRegistries = append(v.DockerRegistries[:i], v.DockerRegistries[i+1:]...)
			v.logHistory("DEL", "DOCKER", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSSHConfig(s SSHConfigEntry) error {
	s.Space = v.CurrentSpace
	v.SSHConfigs = append(v.SSHConfigs, s)
	v.logHistory("ADD", "SSHCONFIG", s.Alias)
	return nil
}

func (v *Vault) DeleteSSHConfig(alias string) bool {
	for i, e := range v.SSHConfigs {
		if e.Alias == alias && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.SSHConfigs = append(v.SSHConfigs[:i], v.SSHConfigs[i+1:]...)
			v.logHistory("DEL", "SSHCONFIG", alias)
			return true
		}
	}
	return false
}

func (v *Vault) AddCICDSecret(c CICDSecretEntry) error {
	c.Space = v.CurrentSpace
	v.CICDSecrets = append(v.CICDSecrets, c)
	v.logHistory("ADD", "CICD", c.Name)
	return nil
}

func (v *Vault) DeleteCICDSecret(name string) bool {
	for i, e := range v.CICDSecrets {
		if e.Name == name && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.CICDSecrets = append(v.CICDSecrets[:i], v.CICDSecrets[i+1:]...)
			v.logHistory("DEL", "CICD", name)
			return true
		}
	}
	return false
}

func (v *Vault) AddSoftwareLicense(s SoftwareLicenseEntry) error {
	s.Space = v.CurrentSpace
	v.SoftwareLicenses = append(v.SoftwareLicenses, s)
	v.logHistory("ADD", "LICENSE", s.ProductName)
	return nil
}

func (v *Vault) DeleteSoftwareLicense(product string) bool {
	for i, e := range v.SoftwareLicenses {
		if e.ProductName == product && (v.CurrentSpace == "" || e.Space == v.CurrentSpace) {
			v.SoftwareLicenses = append(v.SoftwareLicenses[:i], v.SoftwareLicenses[i+1:]...)
			v.logHistory("DEL", "LICENSE", product)
			return true
		}
	}
	return false
}

func (v *Vault) AddLegalContract(l LegalContractEntry) error {
	l.Space = v.CurrentSpace
	v.LegalContracts = append(v.LegalContracts, l)
	v.logHistory("ADD", "CONTRACT", l.Name)
	return nil
}

func (v *Vault) DeleteLegalContract(name string) bool {
	for i, e := range v.LegalContracts {
		if e.Name == name {
			v.LegalContracts = append(v.LegalContracts[:i], v.LegalContracts[i+1:]...)
			v.logHistory("DEL", "CONTRACT", name)
			return true
		}
	}
	return false
}

type SearchResult struct {
	Type       string
	Identifier string
	Data       interface{}
	Space      string
}

func (v *Vault) SearchAll(query string) []SearchResult {
	var results []SearchResult
	query = strings.ToLower(query)

	matchSpace := func(ns string) bool {
		current := v.CurrentSpace
		if current == "" {
			current = "default"
		}
		target := ns
		if target == "" {
			target = "default"
		}
		return current == target
	}

	for _, e := range v.Entries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Account), query)) {
			results = append(results, SearchResult{"Password", e.Account, e, e.Space})
		}
	}
	for _, e := range v.TOTPEntries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Account), query)) {
			results = append(results, SearchResult{"TOTP", e.Account, e, e.Space})
		}
	}
	for _, e := range v.Tokens {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Token", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SecureNotes {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Note", e.Name, e, e.Space})
		}
	}
	for _, e := range v.APIKeys {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"API Key", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SSHKeys {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"SSH Key", e.Name, e, e.Space})
		}
	}
	for _, e := range v.WiFiCredentials {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.SSID), query)) {
			results = append(results, SearchResult{"Wi-Fi", e.SSID, e, e.Space})
		}
	}
	for _, e := range v.RecoveryCodeItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Service), query)) {
			results = append(results, SearchResult{"Recovery Codes", e.Service, e, e.Space})
		}
	}
	for _, e := range v.Certificates {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Certificate", e.Label, e, e.Space})
		}
	}
	for _, e := range v.BankingItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Banking", e.Label, e, e.Space})
		}
	}
	for _, e := range v.Documents {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Document", e.Name, e, e.Space})
		}
	}
	for _, e := range v.AudioFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Audio", e.Name, e, e.Space})
		}
	}
	for _, e := range v.VideoFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Video", e.Name, e, e.Space})
		}
	}
	for _, e := range v.PhotoFiles {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Photo", e.Name, e, e.Space})
		}
	}
	for _, e := range v.GovIDs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.IDNumber), query) || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Government ID", e.IDNumber, e, e.Space})
		}
	}
	for _, e := range v.MedicalRecords {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Medical Record", e.Label, e, e.Space})
		}
	}
	for _, e := range v.TravelDocs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Travel", e.Label, e, e.Space})
		}
	}
	for _, e := range v.Contacts {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Contact", e.Name, e, e.Space})
		}
	}
	for _, e := range v.CloudCredentialsItems {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Label), query)) {
			results = append(results, SearchResult{"Cloud Credentials", e.Label, e, e.Space})
		}
	}
	for _, e := range v.K8sSecrets {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Kubernetes Secret", e.Name, e, e.Space})
		}
	}
	for _, e := range v.DockerRegistries {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Docker Registry", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SSHConfigs {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Alias), query)) {
			results = append(results, SearchResult{"SSH Config", e.Alias, e, e.Space})
		}
	}
	for _, e := range v.CICDSecrets {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"CI/CD Secret", e.Name, e, e.Space})
		}
	}
	for _, e := range v.SoftwareLicenses {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.ProductName), query)) {
			results = append(results, SearchResult{"Software License", e.ProductName, e, e.Space})
		}
	}
	for _, e := range v.LegalContracts {
		if matchSpace(e.Space) && (query == "" || strings.Contains(strings.ToLower(e.Name), query)) {
			results = append(results, SearchResult{"Legal Contract", e.Name, e, e.Space})
		}
	}
	return results
}
