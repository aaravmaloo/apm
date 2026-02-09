package apm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordPolicyValidate(t *testing.T) {
	p := &PasswordPolicy{
		MinLength:      8,
		RequireUpper:   true,
		RequireNumbers: true,
		RequireSymbols: true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"TooShort", "Ab1!", true},
		{"NoUpper", "ab12345!", true},
		{"NoNumber", "Abcdefgh!", true},
		{"NoSymbol", "Abcdefgh1", true},
		{"Valid", "Abcdefgh1!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadPolicies(t *testing.T) {
	tempDir := t.TempDir()

	policy1 := `
name: strict
password_policy:
  min_length: 12
  require_uppercase: true
  require_numbers: true
  require_symbols: true
`
	err := os.WriteFile(filepath.Join(tempDir, "strict.yaml"), []byte(policy1), 0644)
	if err != nil {
		t.Fatalf("Failed to write test policy: %v", err)
	}

	policies, err := LoadPolicies(tempDir)
	if err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policies))
	}

	if policies[0].Name != "strict" {
		t.Errorf("Expected policy name 'strict', got '%s'", policies[0].Name)
	}

	if policies[0].PasswordPolicy.MinLength != 12 {
		t.Errorf("Expected min_length 12, got %d", policies[0].PasswordPolicy.MinLength)
	}
}

func TestLoadPoliciesEmptyDir(t *testing.T) {
	tempDir := t.TempDir()
	policies, err := LoadPolicies(tempDir)
	if err != nil {
		t.Fatalf("LoadPolicies failed on empty dir: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies, got %d", len(policies))
	}
}
