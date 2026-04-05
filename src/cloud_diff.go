package apm

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	VaultDiffAdded    = "added"
	VaultDiffModified = "modified"
	VaultDiffRemoved  = "removed"
)

type VaultDiffChange struct {
	Kind          string
	ItemType      string
	Identifier    string
	Space         string
	ChangedFields []string

	key         vaultDiffKey
	remoteValue any
}

type vaultDiffKey struct {
	ItemType   string
	Identifier string
	Space      string
}

type vaultCollection[T any] struct {
	itemType string
	list     func(*Vault) []T
	set      func(*Vault, []T)
	key      func(T) vaultDiffKey
}

// DiffVaultEntries compares vault content at the entry level so cloud merges
// stay about "what item changed" instead of raw encrypted file differences.
func DiffVaultEntries(local, remote *Vault) []VaultDiffChange {
	if local == nil || remote == nil {
		return nil
	}

	var changes []VaultDiffChange
	appendVaultCollectionDiff(&changes, passwordCollection, local, remote)
	appendVaultCollectionDiff(&changes, totpCollection, local, remote)
	appendVaultCollectionDiff(&changes, tokenCollection, local, remote)
	appendVaultCollectionDiff(&changes, secureNoteCollection, local, remote)
	appendVaultCollectionDiff(&changes, apiKeyCollection, local, remote)
	appendVaultCollectionDiff(&changes, sshKeyCollection, local, remote)
	appendVaultCollectionDiff(&changes, wifiCollection, local, remote)
	appendVaultCollectionDiff(&changes, recoveryCodeCollection, local, remote)
	appendVaultCollectionDiff(&changes, certificateCollection, local, remote)
	appendVaultCollectionDiff(&changes, bankingCollection, local, remote)
	appendVaultCollectionDiff(&changes, documentCollection, local, remote)
	appendVaultCollectionDiff(&changes, audioCollection, local, remote)
	appendVaultCollectionDiff(&changes, videoCollection, local, remote)
	appendVaultCollectionDiff(&changes, photoCollection, local, remote)
	appendVaultCollectionDiff(&changes, govIDCollection, local, remote)
	appendVaultCollectionDiff(&changes, medicalCollection, local, remote)
	appendVaultCollectionDiff(&changes, travelCollection, local, remote)
	appendVaultCollectionDiff(&changes, contactCollection, local, remote)
	appendVaultCollectionDiff(&changes, cloudCredentialCollection, local, remote)
	appendVaultCollectionDiff(&changes, k8sCollection, local, remote)
	appendVaultCollectionDiff(&changes, dockerCollection, local, remote)
	appendVaultCollectionDiff(&changes, sshConfigCollection, local, remote)
	appendVaultCollectionDiff(&changes, cicdCollection, local, remote)
	appendVaultCollectionDiff(&changes, softwareLicenseCollection, local, remote)
	appendVaultCollectionDiff(&changes, legalContractCollection, local, remote)

	sort.Slice(changes, func(i, j int) bool {
		left := strings.ToLower(changes[i].ItemType + "|" + normalizedSpace(changes[i].Space) + "|" + changes[i].Identifier + "|" + changes[i].Kind)
		right := strings.ToLower(changes[j].ItemType + "|" + normalizedSpace(changes[j].Space) + "|" + changes[j].Identifier + "|" + changes[j].Kind)
		return left < right
	})

	return changes
}

// ApplyVaultDiffSelection replays selected remote changes into the local vault
// using collection-aware replacements rather than whole-vault overwrite semantics.
func ApplyVaultDiffSelection(local *Vault, changes []VaultDiffChange, selected []int) error {
	if local == nil {
		return fmt.Errorf("local vault is required")
	}

	for _, idx := range selected {
		if idx < 0 || idx >= len(changes) {
			return fmt.Errorf("invalid change index: %d", idx)
		}

		change := changes[idx]
		applied, err := applyVaultDiffChange(local, change)
		if err != nil {
			return err
		}
		if applied {
			local.logHistory("MERGE", strings.ToUpper(strings.ReplaceAll(change.ItemType, " ", "_")), change.Identifier)
		}
	}

	return nil
}

func appendVaultCollectionDiff[T any](changes *[]VaultDiffChange, cfg vaultCollection[T], local, remote *Vault) {
	localItems := cfg.list(local)
	remoteItems := cfg.list(remote)

	localByKey := make(map[vaultDiffKey]T, len(localItems))
	for _, item := range localItems {
		localByKey[cfg.key(item)] = item
	}

	remoteByKey := make(map[vaultDiffKey]T, len(remoteItems))
	for _, item := range remoteItems {
		remoteByKey[cfg.key(item)] = item
	}

	for key, remoteItem := range remoteByKey {
		localItem, exists := localByKey[key]
		if !exists {
			*changes = append(*changes, VaultDiffChange{
				Kind:        VaultDiffAdded,
				ItemType:    cfg.itemType,
				Identifier:  key.Identifier,
				Space:       key.Space,
				key:         key,
				remoteValue: remoteItem,
			})
			continue
		}

		if reflect.DeepEqual(localItem, remoteItem) {
			continue
		}

		*changes = append(*changes, VaultDiffChange{
			Kind:          VaultDiffModified,
			ItemType:      cfg.itemType,
			Identifier:    key.Identifier,
			Space:         key.Space,
			ChangedFields: changedFieldNames(localItem, remoteItem),
			key:           key,
			remoteValue:   remoteItem,
		})
	}

	for key := range localByKey {
		if _, exists := remoteByKey[key]; exists {
			continue
		}
		*changes = append(*changes, VaultDiffChange{
			Kind:       VaultDiffRemoved,
			ItemType:   cfg.itemType,
			Identifier: key.Identifier,
			Space:      key.Space,
			key:        key,
		})
	}
}

func applyVaultDiffChange(local *Vault, change VaultDiffChange) (bool, error) {
	switch change.ItemType {
	case passwordCollection.itemType:
		return applyCollectionChange(local, change, passwordCollection)
	case totpCollection.itemType:
		return applyCollectionChange(local, change, totpCollection)
	case tokenCollection.itemType:
		return applyCollectionChange(local, change, tokenCollection)
	case secureNoteCollection.itemType:
		return applyCollectionChange(local, change, secureNoteCollection)
	case apiKeyCollection.itemType:
		return applyCollectionChange(local, change, apiKeyCollection)
	case sshKeyCollection.itemType:
		return applyCollectionChange(local, change, sshKeyCollection)
	case wifiCollection.itemType:
		return applyCollectionChange(local, change, wifiCollection)
	case recoveryCodeCollection.itemType:
		return applyCollectionChange(local, change, recoveryCodeCollection)
	case certificateCollection.itemType:
		return applyCollectionChange(local, change, certificateCollection)
	case bankingCollection.itemType:
		return applyCollectionChange(local, change, bankingCollection)
	case documentCollection.itemType:
		return applyCollectionChange(local, change, documentCollection)
	case audioCollection.itemType:
		return applyCollectionChange(local, change, audioCollection)
	case videoCollection.itemType:
		return applyCollectionChange(local, change, videoCollection)
	case photoCollection.itemType:
		return applyCollectionChange(local, change, photoCollection)
	case govIDCollection.itemType:
		return applyCollectionChange(local, change, govIDCollection)
	case medicalCollection.itemType:
		return applyCollectionChange(local, change, medicalCollection)
	case travelCollection.itemType:
		return applyCollectionChange(local, change, travelCollection)
	case contactCollection.itemType:
		return applyCollectionChange(local, change, contactCollection)
	case cloudCredentialCollection.itemType:
		return applyCollectionChange(local, change, cloudCredentialCollection)
	case k8sCollection.itemType:
		return applyCollectionChange(local, change, k8sCollection)
	case dockerCollection.itemType:
		return applyCollectionChange(local, change, dockerCollection)
	case sshConfigCollection.itemType:
		return applyCollectionChange(local, change, sshConfigCollection)
	case cicdCollection.itemType:
		return applyCollectionChange(local, change, cicdCollection)
	case softwareLicenseCollection.itemType:
		return applyCollectionChange(local, change, softwareLicenseCollection)
	case legalContractCollection.itemType:
		return applyCollectionChange(local, change, legalContractCollection)
	default:
		return false, fmt.Errorf("unsupported diff item type: %s", change.ItemType)
	}
}

// applyCollectionChange uses the collection key as the merge identity, which
// lets modified entries replace in place while still preserving adds/removals.
func applyCollectionChange[T any](local *Vault, change VaultDiffChange, cfg vaultCollection[T]) (bool, error) {
	items := cfg.list(local)

	switch change.Kind {
	case VaultDiffAdded, VaultDiffModified:
		remoteItem, ok := change.remoteValue.(T)
		if !ok {
			return false, fmt.Errorf("unexpected remote item payload for %s", change.ItemType)
		}

		replaced := false
		for i := range items {
			if cfg.key(items[i]) == change.key {
				items[i] = remoteItem
				replaced = true
				break
			}
		}
		if !replaced {
			items = append(items, remoteItem)
		}
		cfg.set(local, items)
		return true, nil
	case VaultDiffRemoved:
		filtered := items[:0]
		removed := false
		for _, item := range items {
			if cfg.key(item) == change.key {
				removed = true
				continue
			}
			filtered = append(filtered, item)
		}
		if !removed {
			return false, nil
		}
		cfg.set(local, filtered)
		return true, nil
	default:
		return false, fmt.Errorf("unsupported diff kind: %s", change.Kind)
	}
}

func changedFieldNames(left, right any) []string {
	leftVal := reflect.ValueOf(left)
	rightVal := reflect.ValueOf(right)
	if leftVal.Kind() == reflect.Pointer {
		leftVal = leftVal.Elem()
	}
	if rightVal.Kind() == reflect.Pointer {
		rightVal = rightVal.Elem()
	}

	if !leftVal.IsValid() || !rightVal.IsValid() || leftVal.Type() != rightVal.Type() || leftVal.Kind() != reflect.Struct {
		return nil
	}

	var fields []string
	for i := 0; i < leftVal.NumField(); i++ {
		structField := leftVal.Type().Field(i)
		if !structField.IsExported() {
			continue
		}
		if reflect.DeepEqual(leftVal.Field(i).Interface(), rightVal.Field(i).Interface()) {
			continue
		}
		fields = append(fields, prettyFieldName(structField))
	}

	sort.Strings(fields)
	return fields
}

func prettyFieldName(field reflect.StructField) string {
	tag := strings.TrimSpace(field.Tag.Get("json"))
	if tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			return strings.ReplaceAll(name, "_", " ")
		}
	}
	return strings.ToLower(splitCamelCase(field.Name))
}

func splitCamelCase(value string) string {
	var out []rune
	for i, r := range value {
		if i > 0 && r >= 'A' && r <= 'Z' {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	return string(out)
}

func normalizedSpace(space string) string {
	if strings.TrimSpace(space) == "" {
		return "default"
	}
	return space
}

var passwordCollection = vaultCollection[Entry]{
	itemType: "Password",
	list:     func(v *Vault) []Entry { return v.Entries },
	set:      func(v *Vault, items []Entry) { v.Entries = items },
	key: func(item Entry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Password", Identifier: item.Account, Space: item.Space}
	},
}

var totpCollection = vaultCollection[TOTPEntry]{
	itemType: "TOTP",
	list:     func(v *Vault) []TOTPEntry { return v.TOTPEntries },
	set:      func(v *Vault, items []TOTPEntry) { v.TOTPEntries = items },
	key: func(item TOTPEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "TOTP", Identifier: item.Account, Space: item.Space}
	},
}

var tokenCollection = vaultCollection[TokenEntry]{
	itemType: "Token",
	list:     func(v *Vault) []TokenEntry { return v.Tokens },
	set:      func(v *Vault, items []TokenEntry) { v.Tokens = items },
	key: func(item TokenEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Token", Identifier: item.Name, Space: item.Space}
	},
}

var secureNoteCollection = vaultCollection[SecureNoteEntry]{
	itemType: "Secure Note",
	list:     func(v *Vault) []SecureNoteEntry { return v.SecureNotes },
	set:      func(v *Vault, items []SecureNoteEntry) { v.SecureNotes = items },
	key: func(item SecureNoteEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Secure Note", Identifier: item.Name, Space: item.Space}
	},
}

var apiKeyCollection = vaultCollection[APIKeyEntry]{
	itemType: "API Key",
	list:     func(v *Vault) []APIKeyEntry { return v.APIKeys },
	set:      func(v *Vault, items []APIKeyEntry) { v.APIKeys = items },
	key: func(item APIKeyEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "API Key", Identifier: item.Name, Space: item.Space}
	},
}

var sshKeyCollection = vaultCollection[SSHKeyEntry]{
	itemType: "SSH Key",
	list:     func(v *Vault) []SSHKeyEntry { return v.SSHKeys },
	set:      func(v *Vault, items []SSHKeyEntry) { v.SSHKeys = items },
	key: func(item SSHKeyEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "SSH Key", Identifier: item.Name, Space: item.Space}
	},
}

var wifiCollection = vaultCollection[WiFiEntry]{
	itemType: "Wi-Fi",
	list:     func(v *Vault) []WiFiEntry { return v.WiFiCredentials },
	set:      func(v *Vault, items []WiFiEntry) { v.WiFiCredentials = items },
	key: func(item WiFiEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Wi-Fi", Identifier: item.SSID, Space: item.Space}
	},
}

var recoveryCodeCollection = vaultCollection[RecoveryCodeEntry]{
	itemType: "Recovery Codes",
	list:     func(v *Vault) []RecoveryCodeEntry { return v.RecoveryCodeItems },
	set:      func(v *Vault, items []RecoveryCodeEntry) { v.RecoveryCodeItems = items },
	key: func(item RecoveryCodeEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Recovery Codes", Identifier: item.Service, Space: item.Space}
	},
}

var certificateCollection = vaultCollection[CertificateEntry]{
	itemType: "Certificate",
	list:     func(v *Vault) []CertificateEntry { return v.Certificates },
	set:      func(v *Vault, items []CertificateEntry) { v.Certificates = items },
	key: func(item CertificateEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Certificate", Identifier: item.Label, Space: item.Space}
	},
}

var bankingCollection = vaultCollection[BankingEntry]{
	itemType: "Banking",
	list:     func(v *Vault) []BankingEntry { return v.BankingItems },
	set:      func(v *Vault, items []BankingEntry) { v.BankingItems = items },
	key: func(item BankingEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Banking", Identifier: item.Label, Space: item.Space}
	},
}

var documentCollection = vaultCollection[DocumentEntry]{
	itemType: "Document",
	list:     func(v *Vault) []DocumentEntry { return v.Documents },
	set:      func(v *Vault, items []DocumentEntry) { v.Documents = items },
	key: func(item DocumentEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Document", Identifier: item.Name, Space: item.Space}
	},
}

var audioCollection = vaultCollection[AudioEntry]{
	itemType: "Audio",
	list:     func(v *Vault) []AudioEntry { return v.AudioFiles },
	set:      func(v *Vault, items []AudioEntry) { v.AudioFiles = items },
	key: func(item AudioEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Audio", Identifier: item.Name, Space: item.Space}
	},
}

var videoCollection = vaultCollection[VideoEntry]{
	itemType: "Video",
	list:     func(v *Vault) []VideoEntry { return v.VideoFiles },
	set:      func(v *Vault, items []VideoEntry) { v.VideoFiles = items },
	key: func(item VideoEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Video", Identifier: item.Name, Space: item.Space}
	},
}

var photoCollection = vaultCollection[PhotoEntry]{
	itemType: "Photo",
	list:     func(v *Vault) []PhotoEntry { return v.PhotoFiles },
	set:      func(v *Vault, items []PhotoEntry) { v.PhotoFiles = items },
	key: func(item PhotoEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Photo", Identifier: item.Name, Space: item.Space}
	},
}

var govIDCollection = vaultCollection[GovIDEntry]{
	itemType: "Government ID",
	list:     func(v *Vault) []GovIDEntry { return v.GovIDs },
	set:      func(v *Vault, items []GovIDEntry) { v.GovIDs = items },
	key: func(item GovIDEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Government ID", Identifier: item.IDNumber, Space: item.Space}
	},
}

var medicalCollection = vaultCollection[MedicalRecordEntry]{
	itemType: "Medical Record",
	list:     func(v *Vault) []MedicalRecordEntry { return v.MedicalRecords },
	set:      func(v *Vault, items []MedicalRecordEntry) { v.MedicalRecords = items },
	key: func(item MedicalRecordEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Medical Record", Identifier: item.Label, Space: item.Space}
	},
}

var travelCollection = vaultCollection[TravelEntry]{
	itemType: "Travel",
	list:     func(v *Vault) []TravelEntry { return v.TravelDocs },
	set:      func(v *Vault, items []TravelEntry) { v.TravelDocs = items },
	key: func(item TravelEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Travel", Identifier: item.Label, Space: item.Space}
	},
}

var contactCollection = vaultCollection[ContactEntry]{
	itemType: "Contact",
	list:     func(v *Vault) []ContactEntry { return v.Contacts },
	set:      func(v *Vault, items []ContactEntry) { v.Contacts = items },
	key: func(item ContactEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Contact", Identifier: item.Name, Space: item.Space}
	},
}

var cloudCredentialCollection = vaultCollection[CloudCredentialEntry]{
	itemType: "Cloud Credentials",
	list:     func(v *Vault) []CloudCredentialEntry { return v.CloudCredentialsItems },
	set:      func(v *Vault, items []CloudCredentialEntry) { v.CloudCredentialsItems = items },
	key: func(item CloudCredentialEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Cloud Credentials", Identifier: item.Label, Space: item.Space}
	},
}

var k8sCollection = vaultCollection[K8sSecretEntry]{
	itemType: "Kubernetes Secret",
	list:     func(v *Vault) []K8sSecretEntry { return v.K8sSecrets },
	set:      func(v *Vault, items []K8sSecretEntry) { v.K8sSecrets = items },
	key: func(item K8sSecretEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Kubernetes Secret", Identifier: item.Name, Space: item.Space}
	},
}

var dockerCollection = vaultCollection[DockerRegistryEntry]{
	itemType: "Docker Registry",
	list:     func(v *Vault) []DockerRegistryEntry { return v.DockerRegistries },
	set:      func(v *Vault, items []DockerRegistryEntry) { v.DockerRegistries = items },
	key: func(item DockerRegistryEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Docker Registry", Identifier: item.Name, Space: item.Space}
	},
}

var sshConfigCollection = vaultCollection[SSHConfigEntry]{
	itemType: "SSH Config",
	list:     func(v *Vault) []SSHConfigEntry { return v.SSHConfigs },
	set:      func(v *Vault, items []SSHConfigEntry) { v.SSHConfigs = items },
	key: func(item SSHConfigEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "SSH Config", Identifier: item.Alias, Space: item.Space}
	},
}

var cicdCollection = vaultCollection[CICDSecretEntry]{
	itemType: "CI/CD Secret",
	list:     func(v *Vault) []CICDSecretEntry { return v.CICDSecrets },
	set:      func(v *Vault, items []CICDSecretEntry) { v.CICDSecrets = items },
	key: func(item CICDSecretEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "CI/CD Secret", Identifier: item.Name, Space: item.Space}
	},
}

var softwareLicenseCollection = vaultCollection[SoftwareLicenseEntry]{
	itemType: "Software License",
	list:     func(v *Vault) []SoftwareLicenseEntry { return v.SoftwareLicenses },
	set:      func(v *Vault, items []SoftwareLicenseEntry) { v.SoftwareLicenses = items },
	key: func(item SoftwareLicenseEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Software License", Identifier: item.ProductName, Space: item.Space}
	},
}

var legalContractCollection = vaultCollection[LegalContractEntry]{
	itemType: "Legal Contract",
	list:     func(v *Vault) []LegalContractEntry { return v.LegalContracts },
	set:      func(v *Vault, items []LegalContractEntry) { v.LegalContracts = items },
	key: func(item LegalContractEntry) vaultDiffKey {
		return vaultDiffKey{ItemType: "Legal Contract", Identifier: item.Name, Space: item.Space}
	},
}
