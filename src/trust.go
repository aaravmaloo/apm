package apm

import (
	"os"
	"strings"
	"time"
)

type SecretTelemetry struct {
	CreatedAt      time.Time `json:"created_at,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
	LastAccessed   time.Time `json:"last_accessed,omitempty"`
	LastRotation   time.Time `json:"last_rotation,omitempty"`
	AccessCount    int       `json:"access_count,omitempty"`
	Privilege      string    `json:"privilege,omitempty"`
	Exposed        bool      `json:"exposed,omitempty"`
	CreatedBy      string    `json:"created_by,omitempty"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
	LastAccessedBy string    `json:"last_accessed_by,omitempty"`
	Source         string    `json:"source,omitempty"`
}

func secretTelemetryKey(category, identifier, space string) string {
	return strings.ToUpper(strings.TrimSpace(category)) + "|" + strings.TrimSpace(identifier) + "|" + strings.TrimSpace(space)
}

func parseSecretTelemetryKey(key string) (string, string, string) {
	parts := strings.SplitN(key, "|", 3)
	if len(parts) != 3 {
		return "", key, ""
	}
	return parts[0], parts[1], parts[2]
}

func (v *Vault) ensureSecretTelemetry() {
	if v.SecretTelemetry == nil {
		v.SecretTelemetry = make(map[string]SecretTelemetry)
	}
}

func (v *Vault) TouchSecretTelemetry(category, identifier string, isWrite bool) {
	v.ensureSecretTelemetry()
	key := secretTelemetryKey(category, identifier, v.CurrentSpace)
	now := time.Now()
	actor := resolveTelemetryActor()
	t := v.SecretTelemetry[key]
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
		t.CreatedBy = actor
		if strings.Contains(strings.ToLower(actor), "ai") || strings.EqualFold(strings.ToLower(os.Getenv("APM_CONTEXT")), "mcp") {
			t.Source = "ai"
		} else {
			t.Source = "user"
		}
	}
	if isWrite {
		t.UpdatedAt = now
		t.UpdatedBy = actor
		if t.LastRotation.IsZero() {
			t.LastRotation = now
		}
	}
	t.LastAccessed = now
	t.LastAccessedBy = actor
	t.AccessCount++
	if t.Privilege == "" {
		t.Privilege = "standard"
	}
	v.SecretTelemetry[key] = t
}

func resolveTelemetryActor() string {
	actor := strings.TrimSpace(os.Getenv("APM_ACTOR"))
	if actor != "" {
		return actor
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APM_CONTEXT")), "mcp") {
		return "AI"
	}
	return "User"
}

func (v *Vault) GetSecretTelemetry(category, identifier, space string) (SecretTelemetry, bool) {
	v.ensureSecretTelemetry()
	key := secretTelemetryKey(category, identifier, space)
	if t, ok := v.SecretTelemetry[key]; ok {
		return t, true
	}
	fallbackPrefix := strings.ToUpper(strings.TrimSpace(category)) + "|" + strings.TrimSpace(identifier) + "|"
	for k, t := range v.SecretTelemetry {
		if strings.HasPrefix(k, fallbackPrefix) {
			return t, true
		}
	}
	return SecretTelemetry{}, false
}

func (v *Vault) RemoveSecretTelemetry(category, identifier string) {
	if v.SecretTelemetry == nil {
		return
	}
	delete(v.SecretTelemetry, secretTelemetryKey(category, identifier, v.CurrentSpace))
}
