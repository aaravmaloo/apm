package autofill

import (
	"errors"
	"strings"

	src "password-manager/src"
)

var ErrAmbiguousCredential = errors.New("ambiguous credential profile")
var ErrAmbiguousTOTP = errors.New("ambiguous totp profile")

type resolvedCredential struct {
	Profile  Profile
	Username string
	Password string
	TOTP     string
}

func resolveCredential(vault *src.Vault, profile Profile, includeTOTP bool) (resolvedCredential, error) {
	matches := make([]src.Entry, 0, 2)
	for _, entry := range vault.Entries {
		if !strings.EqualFold(strings.TrimSpace(entry.Account), strings.TrimSpace(profile.EntryAccount)) {
			continue
		}
		if profile.EntryUsername != "" && !strings.EqualFold(strings.TrimSpace(entry.Username), strings.TrimSpace(profile.EntryUsername)) {
			continue
		}
		matches = append(matches, entry)
	}

	if len(matches) == 0 {
		return resolvedCredential{}, errors.New("no credentials found")
	}
	if len(matches) > 1 {
		return resolvedCredential{}, ErrAmbiguousCredential
	}

	cred := resolvedCredential{
		Profile:  profile,
		Username: matches[0].Username,
		Password: matches[0].Password,
	}

	if includeTOTP {
		account := strings.TrimSpace(profile.TOTPAccount)
		if account == "" {
			account = strings.TrimSpace(profile.EntryAccount)
		}
		matches := 0
		for _, t := range vault.TOTPEntries {
			if strings.EqualFold(strings.TrimSpace(t.Account), account) {
				matches++
				if matches > 1 {
					return resolvedCredential{}, ErrAmbiguousTOTP
				}
				code, err := src.GenerateTOTP(t.Secret)
				if err != nil {
					return resolvedCredential{}, err
				}
				cred.TOTP = code
			}
		}
	}

	return cred, nil
}
