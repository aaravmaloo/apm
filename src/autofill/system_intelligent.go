package autofill

import (
	"net/http"
	"sort"
	"strings"
	"unicode"

	src "github.com/aaravmaloo/apm/src"
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
		// Native-app matching is heuristic, so surface explicit choices when the
		// ranking cannot confidently collapse to one credential.
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
	linkedAccounts := linkedTOTPAccountsForContext(vault, ctx)
	emailHints := contextEmailHints(ctx)
	typedEmail := focusedTypedEmail(ctx)
	intent := inferFieldIntent(ctx)

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
			// Pair password entries with their nearest TOTP record up front so the
			// later fill path can decide sequence without another vault scan.
			c.TOTPCount = group.Count
			c.TOTPSecret = group.Secret
			usedTOTPAccount[group.Account] = struct{}{}
		}
		if linkedAccounts[strings.ToLower(strings.TrimSpace(entry.Account))] {
			c.Score += 360
		}
		c.Score += scoreCandidateForIntent(c, intent)
		if c.Score <= 0 {
			continue
		}

		out = append(out, c)
	}

	for accountKey, group := range totpByAccount {
		if _, ok := usedTOTPAccount[accountKey]; ok {
			continue
		}
		if typedEmail != "" {
			// A typed email strongly implies the user wants a password identity, not
			// a standalone OTP-only record.
			continue
		}

		score := scoreAccountContext(group.Account, "", ctx, emailHints)
		if linkedAccounts[accountKey] {
			if score < 800 {
				score = 800
			}
		}
		if score == 0 {
			continue
		}

		c := intelligentCandidate{
			ID:         "totp-" + sanitizeID(group.Account),
			Service:    group.Account,
			Domain:     group.Domain,
			Account:    group.Account,
			TOTPCount:  group.Count,
			TOTPSecret: group.Secret,
			Score:      score,
		}
		c.Score += scoreCandidateForIntent(c, intent)
		if c.Score <= 0 {
			continue
		}
		out = append(out, c)
	}

	sort.SliceStable(out, func(i, j int) bool {
		// Stable secondary ordering keeps repeated ranking runs deterministic when
		// several candidates land on the same score.
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
	if vault == nil {
		return byAccount, byDomain
	}

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
		// Build a domain index so OTP-only sites can still match when the account
		// label differs from the visible app or window title.
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

	for domain, linkedAccount := range vault.TOTPDomainLinks {
		// Explicit user links override inference when the vault carries better
		// domain knowledge than the account label itself.
		domain = normalizeDomain(domain)
		if domain == "" {
			continue
		}
		accountKey := strings.ToLower(strings.TrimSpace(linkedAccount))
		group, ok := byAccount[accountKey]
		if !ok {
			continue
		}
		group.Domain = domain
		byDomain[strings.ToLower(domain)] = group
	}

	return byAccount, byDomain
}

func linkedTOTPAccountsForContext(vault *src.Vault, ctx RequestContext) map[string]bool {
	out := map[string]bool{}
	if vault == nil || len(vault.TOTPDomainLinks) == 0 {
		return out
	}

	hints := normalizeDomainHints(ctx.DomainHints)
	if domain := normalizeDomain(ctx.Domain); domain != "" {
		hints = append(hints, domain)
	}
	if len(hints) == 0 {
		return out
	}

	for domain, account := range vault.TOTPDomainLinks {
		normalizedDomain := strings.ToLower(normalizeDomain(domain))
		if normalizedDomain == "" {
			continue
		}
		for _, hint := range hints {
			if hint == normalizedDomain || strings.HasSuffix(hint, "."+normalizedDomain) || strings.HasSuffix(normalizedDomain, "."+hint) {
				out[strings.ToLower(strings.TrimSpace(account))] = true
			}
		}
	}
	return out
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

	// Domain and window-title signals carry most of the ranking weight because
	// desktop capture is noisier than browser-integrated autofill metadata.
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
		if hintBoost == 0 && score < 220 && !looksLikeOTPWindow(ctx.WindowTitle) {
			// When the focused field already suggests a different identity, avoid
			// weak title-only matches that would fill the wrong account.
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
	intent := inferFieldIntent(ctx)
	switch intent {
	case fieldIntentOTP:
		if totpCode != "" {
			return "{TOTP}"
		}
	case fieldIntentPassword:
		if c.Password != "" {
			return "{PASSWORD}"
		}
	case fieldIntentUsername:
		if c.Username != "" && c.Password != "" && strings.EqualFold(strings.TrimSpace(ctx.FocusedValue), strings.TrimSpace(c.Username)) {
			return "{TAB}{PASSWORD}{ENTER}"
		}
		if c.Username != "" {
			return "{USERNAME}"
		}
	}

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

const (
	fieldIntentUnknown = iota
	fieldIntentUsername
	fieldIntentPassword
	fieldIntentOTP
)

func inferFieldIntent(ctx RequestContext) int {
	name := strings.ToLower(strings.TrimSpace(ctx.FocusedName))
	value := strings.ToLower(strings.TrimSpace(ctx.FocusedValue))
	title := strings.ToLower(strings.TrimSpace(ctx.WindowTitle))

	joined := strings.TrimSpace(name + " " + title)
	if containsAny(joined, "otp", "2fa", "two-factor", "verification", "authenticator", "one-time", "security code") {
		return fieldIntentOTP
	}
	if containsAny(name, "password", "passcode", "pass phrase") {
		return fieldIntentPassword
	}
	if containsAny(name, "email", "username", "user", "login", "identifier") {
		return fieldIntentUsername
	}
	if strings.Contains(value, "@") {
		return fieldIntentUsername
	}
	if isLikelyOTPValue(value) && looksLikeOTPWindow(title) {
		return fieldIntentOTP
	}
	return fieldIntentUnknown
}

func scoreCandidateForIntent(c intelligentCandidate, intent int) int {
	switch intent {
	case fieldIntentOTP:
		if c.TOTPCount == 1 {
			return 600
		}
		if c.TOTPCount > 1 {
			return 260
		}
		if c.HasPassword {
			return -180
		}
	case fieldIntentPassword:
		if c.HasPassword {
			return 320
		}
		return -220
	case fieldIntentUsername:
		if strings.TrimSpace(c.Username) != "" {
			return 280
		}
		if c.HasPassword {
			return 80
		}
		return -120
	}
	return 0
}

func containsAny(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if kw != "" && strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isLikelyOTPValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 8 {
		return false
	}
	digits := 0
	for _, r := range v {
		if unicode.IsDigit(r) {
			digits++
			continue
		}
		if r == ' ' || r == '-' {
			continue
		}
		return false
	}
	return digits >= 3
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
