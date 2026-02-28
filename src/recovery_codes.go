package apm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func normalizeRecoveryCode(input string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(input), " ", ""))
}

func hashRecoveryCode(code string) []byte {
	h := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return h[:]
}

func GenerateOneTimeRecoveryCodes(v *Vault, count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}
	if count > 50 {
		return nil, fmt.Errorf("count too large")
	}
	codes := make([]string, 0, count)
	hashes := make([][]byte, 0, count)
	used := make([]bool, 0, count)

	seen := map[string]bool{}
	for len(codes) < count {
		raw := make([]byte, 5)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		candidate := strings.ToUpper(hex.EncodeToString(raw[:3])) + "-" + strings.ToUpper(hex.EncodeToString(raw[3:]))
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		codes = append(codes, candidate)
		hashes = append(hashes, hashRecoveryCode(candidate))
		used = append(used, false)
	}

	v.RecoveryCodeHashes = hashes
	v.RecoveryCodeUsed = used
	return codes, nil
}

func ValidateRecoveryCodeFromHeader(info RecoveryData, code string) (int, bool) {
	normalized := normalizeRecoveryCode(code)
	if normalized == "" {
		return -1, false
	}
	target := hashRecoveryCode(normalized)
	for i := range info.RecoveryCodeHashes {
		if i < len(info.RecoveryCodeUsed) && info.RecoveryCodeUsed[i] {
			continue
		}
		if hmac.Equal(info.RecoveryCodeHashes[i], target) {
			return i, true
		}
	}
	return -1, false
}

func MarkRecoveryCodeUsed(v *Vault, index int) {
	if index < 0 || index >= len(v.RecoveryCodeUsed) {
		return
	}
	v.RecoveryCodeUsed[index] = true
}

func CountRemainingRecoveryCodes(v *Vault) int {
	remaining := 0
	for i := range v.RecoveryCodeHashes {
		if i >= len(v.RecoveryCodeUsed) || !v.RecoveryCodeUsed[i] {
			remaining++
		}
	}
	return remaining
}
