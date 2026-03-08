package main

import (
	"encoding/json"
	"strings"
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

func GetRoles() []Role {
	return []Role{RoleAdmin, RoleManager, RoleUser, RoleAuditor, RoleSecurity}
}

type EntryMetadata struct {
	ID           string    `json:"id"`
	DepartmentID string    `json:"department_id"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedBy   string    `json:"modified_by"`
	ModifiedAt   time.Time `json:"modified_at"`
	IsSensitive  bool      `json:"is_sensitive"`
	IsGlobal     bool      `json:"is_global"`
}

func (r Role) CanAddEntry(user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["add_entry"]; ok {
			return val
		}
	}
	return r == RoleAdmin || r == RoleManager || r == RoleUser
}

func (r Role) CanEditEntry(createdBy string, currentUser string, user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["edit_entry"]; ok {
			return val
		}
	}
	if r == RoleAdmin || r == RoleManager {
		return true
	}
	return r == RoleUser && createdBy == currentUser
}

func (r Role) CanDeleteEntry(createdBy string, currentUser string, user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["delete_entry"]; ok {
			return val
		}
	}
	if r == RoleAdmin || r == RoleManager {
		return true
	}
	return r == RoleUser && createdBy == currentUser
}

func (r Role) CanShareEntry(user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["share_entry"]; ok {
			return val
		}
	}
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanManageDepartments(user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["manage_depts"]; ok {
			return val
		}
	}
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanManageUsers(user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["manage_users"]; ok {
			return val
		}
	}
	return r == RoleAdmin || r == RoleManager
}

func (r Role) CanViewAudit(user *TeamUser) bool {
	if user != nil && user.Permissions != nil {
		if val, ok := user.Permissions["view_audit"]; ok {
			return val
		}
	}
	return r == RoleAdmin || r == RoleSecurity || r == RoleAuditor
}

type TeamUser struct {
	ID                 string            `json:"id"`
	Username           string            `json:"username"`
	Role               Role              `json:"role"`
	ActiveDepartmentID string            `json:"active_department_id"`
	WrappedKeys        map[string][]byte `json:"wrapped_keys"`
	Permissions        map[string]bool   `json:"permissions"`
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

type ApprovalRequest struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`       // Create, Edit, Delete
	EntryType    string    `json:"entry_type"` // Password, TOTP, etc.
	EntryID      string    `json:"entry_id"`
	NewData      []byte    `json:"new_data"` // JSON marshaled entry
	RequestedBy  string    `json:"requested_by"`
	RequestedAt  time.Time `json:"requested_at"`
	Status       string    `json:"status"` // Pending, Approved, Denied
	DenialReason string    `json:"denial_reason,omitempty"`
}

type SharedPassword struct {
	EntryMetadata
	Name     string `json:"name"`
	Username string `json:"username"`
	Password []byte `json:"password"`
	URL      string `json:"url"`
}

type SharedTOTP struct {
	EntryMetadata
	Name   string `json:"name"`
	Secret []byte `json:"secret"`
	Issuer string `json:"issuer"`
}

type SharedAPIKey struct {
	EntryMetadata
	Label   string `json:"label"`
	Service string `json:"service"`
	Key     []byte `json:"key"`
}

type SharedToken struct {
	EntryMetadata
	Name  string `json:"name"`
	Token []byte `json:"token"`
	Type  string `json:"type"`
}

type SharedNote struct {
	EntryMetadata
	Name    string `json:"name"`
	Content []byte `json:"content"`
}

type SharedSSHKey struct {
	EntryMetadata
	Label      string `json:"label"`
	PrivateKey []byte `json:"private_key"`
}

type SharedCertificate struct {
	EntryMetadata
	Label      string    `json:"label"`
	Issuer     string    `json:"issuer"`
	Expiry     time.Time `json:"expiry"`
	CertData   []byte    `json:"cert_data"`
	PrivateKey []byte    `json:"private_key,omitempty"`
}

type SharedWiFi struct {
	EntryMetadata
	SSID     string `json:"ssid"`
	Password []byte `json:"password"`
	Security string `json:"security"`
}

type SharedRecoveryCode struct {
	EntryMetadata
	Service string `json:"service"`
	Codes   []byte `json:"codes"`
}

type SharedBankingItem struct {
	EntryMetadata
	Label   string `json:"label"`
	Type    string `json:"type"`
	Details []byte `json:"details"`
	CVV     []byte `json:"cvv,omitempty"`
	Expiry  string `json:"expiry,omitempty"`
}

type SharedDocumentEntry struct {
	EntryMetadata
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Content  []byte `json:"content"`
	Password []byte `json:"password"`
}

type SharedGovID struct {
	EntryMetadata
	Type     string `json:"type"`
	IDNumber string `json:"id_number"`
	Name     string `json:"name"`
	Expiry   string `json:"expiry"`
}

type SharedMedicalRecord struct {
	EntryMetadata
	Label         string `json:"label"`
	InsuranceID   string `json:"insurance_id"`
	Prescriptions []byte `json:"prescriptions"`
	Allergies     []byte `json:"allergies"`
}

type SharedTravelDoc struct {
	EntryMetadata
	Label          string `json:"label"`
	TicketNumber   string `json:"ticket_number"`
	BookingCode    []byte `json:"booking_code"`
	LoyaltyProgram string `json:"loyalty_program"`
}

type SharedContact struct {
	EntryMetadata
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Email     string `json:"email"`
	Address   string `json:"address"`
	Emergency bool   `json:"emergency"`
}

type SharedCloudCredential struct {
	EntryMetadata
	Label      string `json:"label"`
	AccessKey  string `json:"access_key"`
	SecretKey  []byte `json:"secret_key"`
	Region     string `json:"region"`
	AccountID  string `json:"account_id"`
	Role       string `json:"role"`
	Expiration string `json:"expiration"`
}

type SharedK8s struct {
	EntryMetadata
	Name         string `json:"name"`
	ClusterURL   string `json:"cluster_url"`
	K8sNamespace string `json:"k8s_namespace"`
	Expiration   string `json:"expiration"`
}

type SharedDockerRegistry struct {
	EntryMetadata
	Name        string `json:"name"`
	RegistryURL string `json:"registry_url"`
	Username    string `json:"username"`
	Token       []byte `json:"token"`
}

type SharedSSHConfig struct {
	EntryMetadata
	Alias       string `json:"alias"`
	Host        string `json:"host"`
	User        string `json:"user"`
	Port        string `json:"port"`
	KeyPath     string `json:"key_path"`
	PrivateKey  []byte `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
}

type SharedCICD struct {
	EntryMetadata
	Name    string `json:"name"`
	Webhook []byte `json:"webhook"`
	EnvVars []byte `json:"env_vars"`
}

type SharedLicenseKey struct {
	EntryMetadata
	ProductName    string `json:"product_name"`
	SerialKey      []byte `json:"serial_key"`
	ActivationInfo string `json:"activation_info"`
	Expiration     string `json:"expiration"`
}

type SharedLegalContract struct {
	EntryMetadata
	Name            string `json:"name"`
	Summary         []byte `json:"summary"`
	PartiesInvolved string `json:"parties_involved"`
	SignedDate      string `json:"signed_date"`
}

type SharedEntryStore struct {
	Passwords        []SharedPassword        `json:"passwords"`
	TOTPs            []SharedTOTP            `json:"totps"`
	APIKeys          []SharedAPIKey          `json:"api_keys"`
	Tokens           []SharedToken           `json:"tokens"`
	Notes            []SharedNote            `json:"notes"`
	SSHKeys          []SharedSSHKey          `json:"ssh_keys"`
	Certificates     []SharedCertificate     `json:"certificates"`
	WiFi             []SharedWiFi            `json:"wifi"`
	RecoveryCodes    []SharedRecoveryCode    `json:"recovery_codes"`
	BankingItems     []SharedBankingItem     `json:"banking_items"`
	Documents        []SharedDocumentEntry   `json:"documents"`
	GovIDs           []SharedGovID           `json:"gov_ids"`
	MedicalRecords   []SharedMedicalRecord   `json:"medical_records"`
	TravelDocs       []SharedTravelDoc       `json:"travel_docs"`
	Contacts         []SharedContact         `json:"contacts"`
	CloudCredentials []SharedCloudCredential `json:"cloud_credentials"`
	K8sSecrets       []SharedK8s             `json:"k8s_secrets"`
	DockerRegistries []SharedDockerRegistry  `json:"docker_registries"`
	SSHConfigs       []SharedSSHConfig       `json:"ssh_configs"`
	CICDSecrets      []SharedCICD            `json:"cicd_secrets"`
	LicenseKeys      []SharedLicenseKey      `json:"license_keys"`
	LegalContracts   []SharedLegalContract   `json:"legal_contracts"`
}

type TeamVault struct {
	OrganizationID   string            `json:"organization_id"`
	Departments      []Department      `json:"departments"`
	Users            []TeamUser        `json:"users"`
	SharedEntries    SharedEntryStore  `json:"shared_entries"`
	Salt             []byte            `json:"salt"`
	AuditTrail       []TeamAuditEntry  `json:"audit_trail"`
	PendingApprovals []ApprovalRequest `json:"pending_approvals"`
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

type SearchResult struct {
	Type       string
	Identifier string
	Data       interface{}
}

func (tv *TeamVault) SearchAll(query string, deptID string, isAdmin bool) []SearchResult {
	var results []SearchResult
	query = strings.ToLower(query)

	checkAccess := func(meta EntryMetadata) bool {
		return isAdmin || meta.IsGlobal || meta.DepartmentID == deptID
	}

	for _, p := range tv.SharedEntries.Passwords {
		if checkAccess(p.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(p.Name), query)) {
			results = append(results, SearchResult{"Password", p.Name, p})
		}
	}
	for _, t := range tv.SharedEntries.TOTPs {
		if checkAccess(t.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(t.Name), query)) {
			results = append(results, SearchResult{"TOTP", t.Name, t})
		}
	}
	for _, k := range tv.SharedEntries.APIKeys {
		if checkAccess(k.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(k.Label), query)) {
			results = append(results, SearchResult{"API Key", k.Label, k})
		}
	}
	for _, t := range tv.SharedEntries.Tokens {
		if checkAccess(t.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(t.Name), query)) {
			results = append(results, SearchResult{"Token", t.Name, t})
		}
	}
	for _, n := range tv.SharedEntries.Notes {
		if checkAccess(n.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(n.Name), query)) {
			results = append(results, SearchResult{"Note", n.Name, n})
		}
	}
	for _, s := range tv.SharedEntries.SSHKeys {
		if checkAccess(s.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(s.Label), query)) {
			results = append(results, SearchResult{"SSH Key", s.Label, s})
		}
	}
	for _, c := range tv.SharedEntries.Certificates {
		if checkAccess(c.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(c.Label), query)) {
			results = append(results, SearchResult{"Certificate", c.Label, c})
		}
	}
	for _, w := range tv.SharedEntries.WiFi {
		if checkAccess(w.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(w.SSID), query)) {
			results = append(results, SearchResult{"Wi-Fi", w.SSID, w})
		}
	}
	for _, r := range tv.SharedEntries.RecoveryCodes {
		if checkAccess(r.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(r.Service), query)) {
			results = append(results, SearchResult{"Recovery Code", r.Service, r})
		}
	}
	for _, b := range tv.SharedEntries.BankingItems {
		if checkAccess(b.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(b.Label), query)) {
			results = append(results, SearchResult{"Banking", b.Label, b})
		}
	}
	for _, d := range tv.SharedEntries.Documents {
		if checkAccess(d.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(d.Name), query)) {
			results = append(results, SearchResult{"Document", d.Name, d})
		}
	}
	for _, g := range tv.SharedEntries.GovIDs {
		if checkAccess(g.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(g.Name), query)) {
			results = append(results, SearchResult{"Gov ID", g.Name, g})
		}
	}
	for _, m := range tv.SharedEntries.MedicalRecords {
		if checkAccess(m.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(m.Label), query)) {
			results = append(results, SearchResult{"Medical Record", m.Label, m})
		}
	}
	for _, t := range tv.SharedEntries.TravelDocs {
		if checkAccess(t.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(t.Label), query)) {
			results = append(results, SearchResult{"Travel", t.Label, t})
		}
	}
	for _, c := range tv.SharedEntries.Contacts {
		if checkAccess(c.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(c.Name), query)) {
			results = append(results, SearchResult{"Contact", c.Name, c})
		}
	}
	for _, c := range tv.SharedEntries.CloudCredentials {
		if checkAccess(c.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(c.Label), query)) {
			results = append(results, SearchResult{"Cloud Credential", c.Label, c})
		}
	}
	for _, k := range tv.SharedEntries.K8sSecrets {
		if checkAccess(k.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(k.Name), query)) {
			results = append(results, SearchResult{"K8s Secret", k.Name, k})
		}
	}
	for _, r := range tv.SharedEntries.DockerRegistries {
		if checkAccess(r.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(r.Name), query)) {
			results = append(results, SearchResult{"Docker Registry", r.Name, r})
		}
	}
	for _, s := range tv.SharedEntries.SSHConfigs {
		if checkAccess(s.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(s.Alias), query)) {
			results = append(results, SearchResult{"SSH Config", s.Alias, s})
		}
	}
	for _, c := range tv.SharedEntries.CICDSecrets {
		if checkAccess(c.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(c.Name), query)) {
			results = append(results, SearchResult{"CI/CD Secret", c.Name, c})
		}
	}
	for _, l := range tv.SharedEntries.LicenseKeys {
		if checkAccess(l.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(l.ProductName), query)) {
			results = append(results, SearchResult{"License Key", l.ProductName, l})
		}
	}
	for _, l := range tv.SharedEntries.LegalContracts {
		if checkAccess(l.EntryMetadata) && (query == "" || strings.Contains(strings.ToLower(l.Name), query)) {
			results = append(results, SearchResult{"Legal Contract", l.Name, l})
		}
	}

	return results
}
