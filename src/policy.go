package apm

import (
	"fmt"
	"os"
	"path/filepath"
	"unicode"

	"gopkg.in/yaml.v3"
)

type PasswordPolicy struct {
	MinLength	int		`yaml:"min_length"`
	RequireUpper	bool		`yaml:"require_uppercase"`
	RequireNumbers	bool		`yaml:"require_numbers"`
	RequireSymbols	bool		`yaml:"require_symbols"`
}

type RotationPolicy struct {
	RotateEveryDays	int		`yaml:"rotate_every_days"`
	NotifyBeforeDays	int		`yaml:"notify_before_days"`
}

type Classification struct {
	MaxAccessLevel	string		`yaml:"max_access_level"`
	MFARequired	bool		`yaml:"mfa_required"`
}

type Policy struct {
	Name	string		`yaml:"name"`
	PasswordPolicy	PasswordPolicy		`yaml:"password_policy"`
	RotationPolicy	RotationPolicy		`yaml:"rotation_policy"`
	Classification	map[string]Classification		`yaml:"classification"`
}

func (p *PasswordPolicy) Validate(password string) error {
	if len(password) < p.MinLength {
		return fmt.Errorf("password too short (min %d)", p.MinLength)
	}
	if p.RequireUpper {
		hasUpper := false
		for _, r := range password {
			if unicode.IsUpper(r) {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			return fmt.Errorf("password must contain an uppercase letter")
		}
	}
	if p.RequireNumbers {
		hasNum := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				hasNum = true
				break
			}
		}
		if !hasNum {
			return fmt.Errorf("password must contain a number")
		}
	}
	if p.RequireSymbols {
		hasSym := false
		for _, r := range password {
			if unicode.IsPunct(r) || unicode.IsSymbol(r) {
				hasSym = true
				break
			}
		}
		if !hasSym {
			return fmt.Errorf("password must contain a symbol")
		}
	}
	return nil
}

func LoadPolicies(dir string) ([]Policy, error) {
	var policies []Policy
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() && (filepath.Ext(file.Name()) == ".yaml" || filepath.Ext(file.Name()) == ".yml") {
			data, err := os.ReadFile(filepath.Join(dir, file.Name()))
			if err != nil {
				continue
			}
			var p Policy
			if err := yaml.Unmarshal(data, &p); err == nil {
				policies = append(policies, p)
			}
		}
	}
	return policies, nil
}
