package autofill

import (
	"net/http"
	"sort"
	"strings"

	src "password-manager/src"
)

type intelligentCandidate struct {
	ID          string
	Service     string
	Domain      string
	Account     string
	Username    string
	Password    string
	HasPassword bool
	TOTPSecret  string
	TOTPCount   int
	Score       int
}

type totpGroup struct {
	Account string
	Domain  string
	Count   int
	Secret  string
}

func resolveSystemIntelligentFill(vault *src.Vault, req FillRequest) (FillResponse, int) {
	candidates := buildIntelligentCandidates(vault, req.Context)
	if len(candidates) == 0 {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "NoMatchingProfileError",
		}, http.StatusNotFound
	}

	if req.SelectionID == "" && len(candidates) > 1 {
		out := make([]MatchCandidate, 0, len(candidates))
		for _, c := range candidates {
			out = append(out, MatchCandidate{
				ProfileID: c.ID,
				Service:   c.Service,
				Domain:    c.Domain,
				Username:  c.Username,
			})
		}
		return FillResponse{
			Status:     ResponseStatusMultiple,
			Candidates: out,
		}, http.StatusOK
	}

	selected, found := pickIntelligentCandidate(candidates, req.SelectionID)
	if !found {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "InvalidSelectionError",
		}, http.StatusBadRequest
	}

	totpCode := ""
	if req.IncludeTOTP {
		if selected.TOTPCount > 1 {
			return FillResponse{
				Status: ResponseStatusOK,
				Error:  "AmbiguousTOTPError",
			}, http.StatusConflict
		}
		if selected.TOTPCount == 1 {
			code, err := src.GenerateTOTP(selected.TOTPSecret)
			if err != nil {
				return FillResponse{
					Status: ResponseStatusOK,
					Error:  "TOTPGenerationError",
				}, http.StatusInternalServerError
			}
			totpCode = code
		}
	}

	sequence := strings.TrimSpace(req.Sequence)
	if sequence == "" {
		sequence = chooseSystemSequence(selected, req.Context, totpCode)
	}

	return FillResponse{
		Status:    ResponseStatusOK,
		ProfileID: selected.ID,
		Service:   selected.Service,
		Domain:    selected.Domain,
		Username:  selected.Username,
		Password:  selected.Password,
		TOTP:      totpCode,
		Sequence:  sequence,
	}, http.StatusOK
}

func buildIntelligentCandidates(vault *src.Vault, ctx RequestContext) []intelligentCandidate {
	totpByAccount, totpByDomain := buildTOTPIndexes(vault)
	emailHints := contextEmailHints(ctx)
	typedEmail := focusedTypedEmail(ctx)

	out := make([]intelligentCandidate, 0, len(vault.Entries)+len(totpByAccount))
	usedTOTPAccount := map[string]struct{}{}

	for _, entry := range vault.Entries {
		if typedEmail != "" && !strings.EqualFold(strings.TrimSpace(entry.Username), typedEmail) {
			continue
		}

		score := scoreAccountContext(entry.Account, entry.Username, ctx, emailHints)
		if score == 0 {
			continue
		}

		c := intelligentCandidate{
			ID:          profileID(entry.Account, entry.Username),
			Service:     entry.Account,
			Domain:      inferDomain(entry.Account),
			Account:     entry.Account,
			Username:    entry.Username,
			Password:    entry.Password,
			HasPassword: true,
			Score:       score,
		}

		group := findMatchingTOTPGroup(entry.Account, totpByAccount, totpByDomain)
		if group != nil {
			c.TOTPCount = group.Count
			c.TOTPSecret = group.Secret
			usedTOTPAccount[group.Account] = struct{}{}
		}

		out = append(out, c)
	}

	for accountKey, group := range totpByAccount {
		if _, ok := usedTOTPAccount[accountKey]; ok {
			continue
		}
		if typedEmail != "" {
			// In typed-email mode we only autofill credentials tied to that exact
			// username and skip standalone TOTP-only guesses.
			continue
		}

		score := scoreAccountContext(group.Account, "", ctx, emailHints)
		if score == 0 {
			continue
		}

		out = append(out, intelligentCandidate{
			ID:         "totp-" + sanitizeID(group.Account),
			Service:    group.Account,
			Domain:     group.Domain,
			Account:    group.Account,
			TOTPCount:  group.Count,
			TOTPSecret: group.Secret,
			Score:      score,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		left := strings.ToLower(out[i].Service + "|" + out[i].Username + "|" + out[i].ID)
		right := strings.ToLower(out[j].Service + "|" + out[j].Username + "|" + out[j].ID)
		return left < right
	})
	return out
}

func buildTOTPIndexes(vault *src.Vault) (map[string]totpGroup, map[string]totpGroup) {
	byAccount := map[string]totpGroup{}
	byDomain := map[string]totpGroup{}

	for _, t := range vault.TOTPEntries {
		account := strings.TrimSpace(t.Account)
		if account == "" {
			continue
		}
		accountKey := strings.ToLower(account)
		group := byAccount[accountKey]
		group.Account = account
		group.Domain = inferDomain(account)
		group.Count++
		if group.Count == 1 {
			group.Secret = t.Secret
		}
		byAccount[accountKey] = group
	}

	for _, group := range byAccount {
		if group.Domain == "" {
			continue
		}
		domainKey := strings.ToLower(group.Domain)
		agg := byDomain[domainKey]
		if agg.Account == "" {
			agg.Account = group.Account
		}
		agg.Domain = group.Domain
		agg.Count += group.Count
		if agg.Count == group.Count {
			agg.Secret = group.Secret
		}
		byDomain[domainKey] = agg
	}

	return byAccount, byDomain
}

func findMatchingTOTPGroup(account string, byAccount map[string]totpGroup, byDomain map[string]totpGroup) *totpGroup {
	accountKey := strings.ToLower(strings.TrimSpace(account))
	if accountKey != "" {
		if group, ok := byAccount[accountKey]; ok {
			return &group
		}
	}

	domain := strings.ToLower(inferDomain(account))
	if domain != "" {
		if group, ok := byDomain[domain]; ok {
			return &group
		}
	}
	return nil
}

func scoreAccountContext(account, username string, ctx RequestContext, emailHints []string) int {
	accountLower := strings.ToLower(strings.TrimSpace(account))
	if accountLower == "" {
		return 0
	}

	title := strings.ToLower(strings.TrimSpace(ctx.WindowTitle))
	process := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ctx.ProcessName)), ".exe")
	domain := strings.ToLower(strings.TrimSpace(normalizeDomain(ctx.Domain)))
	domainHints := normalizeDomainHints(ctx.DomainHints)

	score := 0

	accountDomain := inferDomain(accountLower)
	if domain != "" && accountDomain != "" {
		if accountDomain == domain || strings.HasSuffix(domain, "."+accountDomain) || strings.HasSuffix(accountDomain, "."+domain) {
			score += 400
		}
	}
	if accountDomain != "" && len(domainHints) > 0 {
		best := 0
		for _, hint := range domainHints {
			if accountDomain == hint || strings.HasSuffix(hint, "."+accountDomain) || strings.HasSuffix(accountDomain, "."+hint) {
				if best < 360 {
					best = 360
				}
			}
		}
		score += best
	}

	if accountDomain != "" {
		label := firstDomainLabel(accountDomain)
		if strings.Contains(title, accountDomain) {
			score += 220
		}
		if label != "" && strings.Contains(title, label) {
			score += 140
		}
		if label != "" && process == label {
			score += 180
		}
	}

	if strings.Contains(title, accountLower) {
		score += 120
	}
	if process != "" && strings.Contains(accountLower, process) {
		score += 80
	}

	for _, token := range accountTokens(accountLower) {
		if len(token) < 4 {
			continue
		}
		if strings.Contains(title, token) {
			score += 25
		}
	}

	usernameLower := strings.ToLower(strings.TrimSpace(username))
	if usernameLower != "" && strings.Contains(title, usernameLower) {
		score += 30
	}

	if len(emailHints) > 0 {
		hintBoost := scoreEmailHint(usernameLower, accountLower, emailHints)
		if hintBoost == 0 && score < 220 {
			return 0
		}
		score += hintBoost
	}

	return score
}

func normalizeDomainHints(hints []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(hints))
	for _, hint := range hints {
		d := strings.ToLower(strings.TrimSpace(normalizeDomain(hint)))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func scoreEmailHint(usernameLower, accountLower string, emailHints []string) int {
	best := 0
	accountDomain := inferDomain(accountLower)
	for _, hint := range emailHints {
		hint = strings.ToLower(strings.TrimSpace(hint))
		if hint == "" {
			continue
		}
		if usernameLower != "" && hint == usernameLower {
			if best < 1200 {
				best = 1200
			}
			continue
		}
		if hint == accountLower {
			if best < 1000 {
				best = 1000
			}
			continue
		}
		if strings.Contains(accountLower, hint) || strings.Contains(hint, accountLower) {
			if best < 750 {
				best = 750
			}
		}
		if accountDomain != "" {
			hintDomain := inferDomain(hint)
			if hintDomain != "" && (hintDomain == accountDomain || strings.HasSuffix(accountDomain, "."+hintDomain) || strings.HasSuffix(hintDomain, "."+accountDomain)) {
				if best < 280 {
					best = 280
				}
			}
		}
	}
	return best
}

func contextEmailHints(ctx RequestContext) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 6)

	for _, hint := range ctx.EmailHints {
		h := strings.ToLower(strings.TrimSpace(hint))
		if h == "" {
			continue
		}
		if _, exists := seen[h]; exists {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}

	fromFocused := extractEmailHints([]string{ctx.FocusedValue, ctx.FocusedName})
	for _, hint := range fromFocused {
		if _, exists := seen[hint]; exists {
			continue
		}
		seen[hint] = struct{}{}
		out = append(out, hint)
	}

	return out
}

func focusedTypedEmail(ctx RequestContext) string {
	matches := extractEmailHints([]string{ctx.FocusedValue})
	if len(matches) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(matches[0]))
}

func firstDomainLabel(domain string) string {
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func accountTokens(value string) []string {
	split := strings.FieldsFunc(value, func(r rune) bool {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= '0' && r <= '9' {
			return false
		}
		return true
	})

	unique := map[string]struct{}{}
	out := make([]string, 0, len(split))
	for _, token := range split {
		token = strings.TrimSpace(strings.ToLower(token))
		if token == "" {
			continue
		}
		if _, exists := unique[token]; exists {
			continue
		}
		unique[token] = struct{}{}
		out = append(out, token)
	}
	return out
}

func chooseSystemSequence(c intelligentCandidate, ctx RequestContext, totpCode string) string {
	if looksLikeOTPWindow(ctx.WindowTitle) && totpCode != "" {
		return "{TOTP}"
	}
	if c.Username != "" && c.Password != "" {
		if strings.EqualFold(strings.TrimSpace(ctx.FocusedValue), strings.TrimSpace(c.Username)) {
			return "{TAB}{PASSWORD}{ENTER}"
		}
	}
	if c.Username != "" && c.Password != "" {
		return DefaultSequenceTemplate
	}
	if c.Password != "" {
		return "{PASSWORD}"
	}
	if c.Username != "" {
		return "{USERNAME}"
	}
	if totpCode != "" {
		return "{TOTP}"
	}
	return DefaultSequenceTemplate
}

func looksLikeOTPWindow(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	if title == "" {
		return false
	}
	keywords := []string{
		"two-factor",
		"2fa",
		"otp",
		"verification code",
		"one-time",
		"authenticator",
		"verify",
	}
	for _, kw := range keywords {
		if strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func pickIntelligentCandidate(matches []intelligentCandidate, selectionID string) (intelligentCandidate, bool) {
	if len(matches) == 1 && strings.TrimSpace(selectionID) == "" {
		return matches[0], true
	}
	for _, m := range matches {
		if strings.EqualFold(strings.TrimSpace(m.ID), strings.TrimSpace(selectionID)) {
			return m, true
		}
	}
	return intelligentCandidate{}, false
}
