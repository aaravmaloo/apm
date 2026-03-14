package autofill

import (
	"sort"
	"strings"
)

func matchProfiles(profiles []Profile, ctx RequestContext) []Profile {
	type scored struct {
		profile Profile
		score   int
	}

	result := make([]scored, 0, len(profiles))
	for _, profile := range profiles {
		score, ok := scoreProfile(profile, ctx)
		if !ok {
			continue
		}
		result = append(result, scored{profile: profile, score: score})
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].score != result[j].score {
			return result[i].score > result[j].score
		}
		left := strings.ToLower(result[i].profile.Service + "|" + result[i].profile.EntryUsername + "|" + result[i].profile.ID)
		right := strings.ToLower(result[j].profile.Service + "|" + result[j].profile.EntryUsername + "|" + result[j].profile.ID)
		return left < right
	})

	out := make([]Profile, 0, len(result))
	for _, s := range result {
		out = append(out, s.profile)
	}
	return out
}

func scoreProfile(profile Profile, ctx RequestContext) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(ctx.Kind)) {
	case ContextBrowser:
		return scoreBrowserProfile(profile, ctx)
	case ContextSystem:
		return scoreSystemProfile(profile, ctx)
	default:
		return 0, false
	}
}

func scoreBrowserProfile(profile Profile, ctx RequestContext) (int, bool) {
	domain := normalizeDomain(ctx.Domain)
	if domain == "" {
		return 0, false
	}

	candidates := make([]string, 0, 1+len(profile.Domains))
	if profile.Domain != "" {
		candidates = append(candidates, profile.Domain)
	}
	candidates = append(candidates, profile.Domains...)
	if len(candidates) == 0 {
		return 0, false
	}

	best := 0
	for _, cand := range candidates {
		cand = normalizeDomain(cand)
		if cand == "" {
			continue
		}
		if cand == domain {
			if best < 300 {
				best = 300
			}
			continue
		}
		if strings.HasSuffix(domain, "."+cand) {
			if best < 200 {
				best = 200
			}
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

func scoreSystemProfile(profile Profile, ctx RequestContext) (int, bool) {
	process := strings.ToLower(strings.TrimSpace(ctx.ProcessName))
	windowTitle := strings.ToLower(strings.TrimSpace(ctx.WindowTitle))
	if process == "" && windowTitle == "" {
		return 0, false
	}

	score := 0

	if len(profile.ProcessNames) > 0 {
		if process == "" {
			return 0, false
		}
		matched := false
		for _, allowed := range profile.ProcessNames {
			if allowed != "" && strings.EqualFold(process, strings.TrimSpace(allowed)) {
				matched = true
				break
			}
		}
		if !matched {
			return 0, false
		}
		score += 250
	}

	if len(profile.WindowContains) > 0 {
		if windowTitle == "" {
			return 0, false
		}
		matched := false
		for _, contains := range profile.WindowContains {
			contains = strings.ToLower(strings.TrimSpace(contains))
			if contains != "" && strings.Contains(windowTitle, contains) {
				matched = true
				break
			}
		}
		if !matched {
			return 0, false
		}
		score += 150
	}

	if len(profile.ProcessNames) == 0 && len(profile.WindowContains) == 0 {
		return 0, false
	}

	if score == 0 {
		return 0, false
	}
	return score, true
}
