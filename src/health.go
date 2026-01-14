package apm

import (
	"fmt"
)

// Health Dashboard logic

func CalculateHealth(vault *Vault) (int, []string) {
	score := 100
	var report []string

	// Profile check
	prof := GetProfile(vault.Profile)
	if vault.Profile == "" {
		prof = ProfileStandard
	}

	if prof.Name == "hardened" || prof.Name == "paranoid" {
		report = append(report, fmt.Sprintf("Encryption profile: %s (+20)", prof.Name))
		// Bonus already included in base? Or add bonus?
		// Let's say base is 60.
		// Standard: +0
		// Hardened: +20
		// logic:
	} else if prof.Name == "legacy" {
		score -= 20
		report = append(report, "Legacy profile used (-20)")
	} else {
		report = append(report, "Standard encryption used (OK)")
	}

	if vault.AlertsEnabled {
		score += 10
		if score > 100 {
			score = 100
		} // Cap at 100? Or base is 80?
		report = append(report, "Alerts enabled: yes (+10)")
	} else {
		score -= 10
		report = append(report, "Alerts disabled: no (-10)")
	}

	// Weak passwords / Reused (Mock logic, would iterate Entries)
	weakCount := 0
	for _, e := range vault.Entries {
		if len(e.Password) < 8 {
			weakCount++
		}
	}
	if weakCount > 0 {
		penalty := weakCount * 5
		score -= penalty
		report = append(report, fmt.Sprintf("Weak secrets: %d (-%d)", weakCount, penalty))
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score, report
}
