package apm

import (
	"fmt"
	"os"
	"sort"
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

type SecretTrustScore struct {
	Category   string
	Identifier string
	Space      string
	Score      int
	Risk       string
	Reasons    []string
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

func trustRiskLabel(score int) string {
	switch {
	case score >= 80:
		return "low"
	case score >= 55:
		return "medium"
	case score >= 35:
		return "high"
	default:
		return "critical"
	}
}

func (v *Vault) ComputeSecretTrustScores() []SecretTrustScore {
	v.ensureSecretTelemetry()
	if len(v.SecretTelemetry) == 0 {
		return nil
	}

	now := time.Now()
	scores := make([]SecretTrustScore, 0, len(v.SecretTelemetry))
	for key, t := range v.SecretTelemetry {
		category, identifier, space := parseSecretTelemetryKey(key)
		score := 100
		reasons := []string{}

		if t.Exposed {
			score -= 45
			reasons = append(reasons, "secret marked as exposed")
		}

		if !t.LastRotation.IsZero() {
			days := int(now.Sub(t.LastRotation).Hours() / 24)
			switch {
			case days > 365:
				score -= 35
				reasons = append(reasons, "rotation older than 365 days")
			case days > 180:
				score -= 20
				reasons = append(reasons, "rotation older than 180 days")
			case days > 90:
				score -= 10
				reasons = append(reasons, "rotation older than 90 days")
			}
		}

		if t.AccessCount > 200 {
			score -= 20
			reasons = append(reasons, "high access frequency")
		} else if t.AccessCount > 75 {
			score -= 10
			reasons = append(reasons, "elevated access frequency")
		}

		switch strings.ToLower(t.Privilege) {
		case "critical", "root", "admin":
			score -= 15
			reasons = append(reasons, "high-privilege secret")
		case "elevated":
			score -= 8
			reasons = append(reasons, "elevated privilege secret")
		}

		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}

		scores = append(scores, SecretTrustScore{
			Category:   category,
			Identifier: identifier,
			Space:      space,
			Score:      score,
			Risk:       trustRiskLabel(score),
			Reasons:    reasons,
		})
	}

	sort.Slice(scores, func(i, j int) bool {
		if scores[i].Score == scores[j].Score {
			return fmt.Sprintf("%s/%s", scores[i].Category, scores[i].Identifier) < fmt.Sprintf("%s/%s", scores[j].Category, scores[j].Identifier)
		}
		return scores[i].Score < scores[j].Score
	})

	return scores
}
