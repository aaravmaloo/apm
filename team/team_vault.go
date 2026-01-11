package main

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleAdmin    Role = "ADMIN"
	RoleManager  Role = "MANAGER"
	RoleUser     Role = "USER"
	RoleAuditor  Role = "AUDITOR"
	RoleSecurity Role = "SECURITY"
)

func (r Role) CanAddEntry() bool {
	return r == RoleAdmin || r == RoleManager || r == RoleUser
}

func (r Role) CanEditEntry(createdBy string, currentUser string) bool {
	if r == RoleAdmin || r == RoleManager {
		return true
	}
	return r == RoleUser && createdBy == currentUser
}

func (r Role) CanDeleteEntry(createdBy string, currentUser string) bool {
	if r == RoleAdmin || r == RoleManager {
		return true
	}
	return r == RoleUser && createdBy == currentUser
}

func (r Role) CanShareEntry() bool {
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanManageDepartments() bool {
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanManageUsers() bool {
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanViewAudit() bool {
	return r == RoleAdmin || r == RoleSecurity || r == RoleAuditor
}

type TeamUser struct {
	ID                 string            `json:"id"`
	Username           string            `json:"username"`
	Role               Role              `json:"role"`
	ActiveDepartmentID string            `json:"active_department_id"`
	WrappedKeys        map[string][]byte `json:"wrapped_keys"`
}

type Department struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	EncryptedKey []byte `json:"encrypted_key,omitempty"`
}

type TeamAuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	PrevHash  string    `json:"prev_hash"`
}

type SharedPassword struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Username     string    `json:"username"`
	Password     []byte    `json:"password"`
	URL          string    `json:"url"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedBy   string    `json:"modified_by"`
	ModifiedAt   time.Time `json:"modified_at"`
}

type SharedTOTP struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Secret       []byte    `json:"secret"`
	Issuer       string    `json:"issuer"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedAPIKey struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Service      string    `json:"service"`
	Key          []byte    `json:"key"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedBy   string    `json:"modified_by"`
	ModifiedAt   time.Time `json:"modified_at"`
}

type SharedToken struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Token        []byte    `json:"token"`
	Type         string    `json:"type"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedNote struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Content      []byte    `json:"content"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedBy   string    `json:"modified_by"`
	ModifiedAt   time.Time `json:"modified_at"`
}

type SharedSSHKey struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	PrivateKey   []byte    `json:"private_key"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedCertificate struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	Issuer       string    `json:"issuer"`
	Expiry       time.Time `json:"expiry"`
	CertData     []byte    `json:"cert_data"`
	PrivateKey   []byte    `json:"private_key,omitempty"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedWiFi struct {
	ID           string    `json:"id"`
	SSID         string    `json:"ssid"`
	Password     []byte    `json:"password"`
	Security     string    `json:"security"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedRecoveryCode struct {
	ID           string    `json:"id"`
	Service      string    `json:"service"`
	Codes        []byte    `json:"codes"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type SharedEntryStore struct {
	Passwords     []SharedPassword     `json:"passwords"`
	TOTPs         []SharedTOTP         `json:"totps"`
	APIKeys       []SharedAPIKey       `json:"api_keys"`
	Tokens        []SharedToken        `json:"tokens"`
	Notes         []SharedNote         `json:"notes"`
	SSHKeys       []SharedSSHKey       `json:"ssh_keys"`
	Certificates  []SharedCertificate  `json:"certificates"`
	WiFi          []SharedWiFi         `json:"wifi"`
	RecoveryCodes []SharedRecoveryCode `json:"recovery_codes"`
}

type TeamVault struct {
	OrganizationID string           `json:"organization_id"`
	Departments    []Department     `json:"departments"`
	Users          []TeamUser       `json:"users"`
	SharedEntries  SharedEntryStore `json:"shared_entries"`
	Salt           []byte           `json:"salt"`
	AuditTrail     []TeamAuditEntry `json:"audit_trail"`
}

func (tv *TeamVault) AddAuditEntry(user, action, details string) {
	entry := TeamAuditEntry{
		Timestamp: time.Now(),
		User:      user,
		Action:    action,
		Details:   details,
	}
	if len(tv.AuditTrail) > 0 {
		lastEntry := tv.AuditTrail[len(tv.AuditTrail)-1]
		data, _ := json.Marshal(lastEntry)
		entry.PrevHash = hashData(data)
	}
	tv.AuditTrail = append(tv.AuditTrail, entry)
}
