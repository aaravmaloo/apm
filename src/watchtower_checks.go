package apm

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// wtItem is one vault item as the checks see it.
type wtItem struct {
	ref        VaultItemRef
	title      string
	tel        SecretTelemetry
	password   string
	username   string
	site       *url.URL
	privileged bool
}

func itoa(n int) string { return strconv.Itoa(n) }

func watchtowerItems(v *Vault) []*wtItem {
	refs := v.ItemRefs()
	out := make([]*wtItem, 0, len(refs))
	for _, ref := range refs {
		it := &wtItem{ref: ref, title: ref.Title, tel: v.ItemTelemetry(ref)}
		if strings.TrimSpace(it.title) == "" {
			it.title = "Untitled " + ref.Spec.ID
		}
		it.privileged = privilegedTelemetry(it.tel)
		switch ref.Spec.ID {
		case "password":
			e := v.Entries[ref.Index]
			it.password = e.Password
			it.username = e.Username
			for _, raw := range append([]string{e.Website}, e.URLs...) {
				if u, ok := siteURL(raw); ok {
					it.site = u
					break
				}
			}
		case "wifi":
			it.password = v.WiFiCredentials[ref.Index].Password
		}
		out = append(out, it)
	}
	return out
}

func (it *wtItem) finding(kind, sev, title, body string, fixes ...string) Finding {
	if it.privileged {
		sev = bumpSeverity(sev)
	}
	f := Finding{
		ID: kind + ":" + it.ref.ID, Kind: kind, Severity: sev, Title: title, Body: body,
		ItemID: it.ref.ID, ItemType: it.ref.Spec.ID, ItemTitle: it.title, Space: it.ref.Space,
		Fixes: fixes,
	}
	if f.Fixes == nil {
		f.Fixes = []string{}
	}
	if it.site != nil {
		f.URL = it.site.Scheme + "://" + it.site.Host
	}
	return f
}

// passwordFixes are the actions for a password that should change. The
// site's change-password page comes second when the login has a site.
func (it *wtItem) passwordFinding(kind, sev, title, body string) Finding {
	fixes := []string{"change_password"}
	if it.ref.Spec.ID != "password" {
		fixes = []string{"rotate"}
	}
	f := it.finding(kind, sev, title, body, fixes...)
	if it.site != nil {
		if cu := changePasswordURL(it.site); cu != "" {
			f.ChangeURL = cu
			f.Fixes = append(f.Fixes, "open_change_url")
		}
	}
	return f
}

func siteWords(it *wtItem) []string {
	words := []string{it.username, it.title}
	if it.site != nil {
		d := RegistrableDomain(it.site.Hostname())
		if i := strings.Index(d, "."); i > 0 {
			words = append(words, d[:i])
		}
	}
	if at := strings.Index(it.username, "@"); at > 0 {
		words = append(words, it.username[:at])
	}
	return words
}

func describeStrength(s StrengthResult, length int) string {
	var parts []string
	if s.Common {
		return "It is one of the most common passwords, so it is among the first an attacker tries."
	}
	if s.Short {
		parts = append(parts, "Only "+itoa(length)+" characters.")
	}
	if len(s.Reasons) > 0 {
		r := s.Reasons
		list := r[0]
		if len(r) > 1 {
			list = strings.Join(r[:len(r)-1], ", ") + " and " + r[len(r)-1]
		}
		parts = append(parts, "It uses "+list+".")
	}
	parts = append(parts, "About "+itoa(int(s.Bits))+" bits, guessed "+crackTime(s.Bits)+" offline.")
	return strings.Join(parts, " ")
}

// crackTime assumes 10 billion guesses a second against a fast hash.
func crackTime(bits float64) string {
	secs := pow2(bits) / 1e10
	switch {
	case secs < 1:
		return "instantly"
	case secs < 3600:
		return "in minutes"
	case secs < 86400:
		return "in hours"
	case secs < 86400*30:
		return "in days"
	case secs < 86400*365:
		return "in months"
	case secs < 86400*365*100:
		return "in years"
	}
	return "in centuries"
}

func pow2(b float64) float64 {
	r := 1.0
	for b >= 1 {
		r *= 2
		b--
	}
	return r * (1 + b)
}

// checkPasswords covers weak, reused, old and breached passwords. Reuse is
// found across every space, then limited to scoped like the rest.
func checkPasswords(v *Vault, all, scoped []*wtItem, now time.Time, eligible map[string]int) []Finding {
	inScope := map[string]bool{}
	for _, it := range scoped {
		inScope[it.ref.ID] = true
	}
	var withPw []*wtItem
	for _, it := range all {
		if it.password != "" {
			withPw = append(withPw, it)
		}
	}
	var out []Finding
	for _, it := range withPw {
		if !inScope[it.ref.ID] {
			continue
		}
		for _, k := range []string{"weak", "reused", "old", "breached"} {
			eligible[k]++
		}
		s := PasswordStrength(it.password, siteWords(it)...)
		length := len([]rune(it.password))
		switch {
		case s.Common:
			out = append(out, it.passwordFinding("weak", SeverityCritical, "Common password", describeStrength(s, length)))
		case s.Weak():
			title := "Easy to guess"
			if s.Short {
				title = "Short password"
			}
			out = append(out, it.passwordFinding("weak", SeverityHigh, title, describeStrength(s, length)))
		case s.Bits < 36:
			out = append(out, it.passwordFinding("weak", SeverityMedium, "Could be stronger", describeStrength(s, length)))
		}

		since := it.tel.LastRotation
		if since.IsZero() {
			since = it.tel.UpdatedAt
		}
		if since.IsZero() {
			since = it.tel.CreatedAt
		}
		if !since.IsZero() {
			days := int(now.Sub(since).Hours() / 24)
			if days > 180 {
				sev := SeverityLow
				if days > 365 {
					sev = SeverityMedium
				}
				out = append(out, it.passwordFinding("old", sev, "Not changed in "+ageText(days), "Last changed "+since.Local().Format("Jan 2, 2006")+"."))
			}
		}

		if n, ok := breachCount(v, it.ref.ID, it.password); ok && n > 0 {
			out = append(out, it.passwordFinding("breached", SeverityCritical, "Found in a data breach",
				"This password appears "+commaInt(n)+" times in known breaches. Change it everywhere you use it."))
		}
	}
	out = append(out, reuseFindings(withPw, inScope)...)
	return out
}

func ageText(days int) string {
	if days >= 730 {
		return itoa(days/365) + " years"
	}
	if days > 365 {
		return "over a year"
	}
	return itoa(days/30) + " months"
}

func commaInt(n int) string {
	s := itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

var trailingNoise = regexp.MustCompile(`[\d\W_]+$`)

// reuseBase strips trailing digits and symbols: Summer2023! and Summer2024!
// share "summer".
func reuseBase(pw string) string {
	b := strings.ToLower(trailingNoise.ReplaceAllString(pw, ""))
	if len([]rune(b)) < 4 {
		return ""
	}
	return b
}

// withinEdits reports whether a and b are at most max edits apart.
func withinEdits(a, b []rune, max int) bool {
	if d := len(a) - len(b); d > max || d < -max {
		return false
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		rowMin := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			rowMin = min(rowMin, cur[j])
		}
		if rowMin > max {
			return false
		}
		prev, cur = cur, prev
	}
	return prev[len(b)] <= max
}

func reuseFindings(items []*wtItem, inScope map[string]bool) []Finding {
	n := len(items)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	exact := map[int]map[int]bool{}
	link := func(i, j int, same bool) {
		parent[find(i)] = find(j)
		if same {
			if exact[i] == nil {
				exact[i] = map[int]bool{}
			}
			if exact[j] == nil {
				exact[j] = map[int]bool{}
			}
			exact[i][j], exact[j][i] = true, true
		}
	}
	byPw := map[string]int{}
	byBase := map[string]int{}
	runes := make([][]rune, n)
	for i, it := range items {
		runes[i] = []rune(it.password)
		if j, ok := byPw[it.password]; ok {
			link(i, j, true)
			for k := range exact[j] {
				link(i, k, true)
			}
		} else {
			byPw[it.password] = i
		}
		if b := reuseBase(it.password); b != "" {
			if j, ok := byBase[b]; ok {
				link(i, j, false)
			} else {
				byBase[b] = i
			}
		}
	}
	// Near reuse by edit distance, only between distinct long passwords.
	var long []int
	for pw, i := range byPw {
		if len([]rune(pw)) >= 8 {
			long = append(long, i)
		}
	}
	sort.Ints(long)
	for a := 0; a < len(long); a++ {
		for b := a + 1; b < len(long); b++ {
			i, j := long[a], long[b]
			if find(i) == find(j) {
				continue
			}
			if withinEdits(runes[i], runes[j], 2) {
				link(i, j, false)
			}
		}
	}

	groups := map[int][]int{}
	for i := range items {
		groups[find(i)] = append(groups[find(i)], i)
	}
	var out []Finding
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		ids := make([]string, 0, len(members))
		for _, m := range members {
			ids = append(ids, items[m].ref.ID)
		}
		sort.Strings(ids)
		group := "reuse-" + shortHash(strings.Join(ids, ","))
		for _, m := range members {
			it := items[m]
			if !inScope[it.ref.ID] {
				continue
			}
			var same, near []string
			for _, o := range members {
				if o == m {
					continue
				}
				if items[o].password == it.password {
					same = append(same, items[o].title)
				} else {
					near = append(near, items[o].title)
				}
			}
			sort.Strings(same)
			sort.Strings(near)
			var f Finding
			if len(same) > 0 {
				body := "Also used by " + joinTitles(same) + "."
				if len(near) > 0 {
					body += " Almost the same as " + joinTitles(near) + "."
				}
				f = it.passwordFinding("reused", SeverityHigh, "Reused password", body)
			} else {
				f = it.passwordFinding("reused", SeverityMedium, "Similar password", "Almost the same as "+joinTitles(near)+". A leak of one makes the others easy to guess.")
			}
			f.Group = group
			out = append(out, f)
		}
	}
	return out
}

func joinTitles(t []string) string {
	if len(t) > 3 {
		return strings.Join(t[:3], ", ") + " and " + itoa(len(t)-3) + " more"
	}
	if len(t) <= 1 {
		return strings.Join(t, "")
	}
	return strings.Join(t[:len(t)-1], ", ") + " and " + t[len(t)-1]
}

// expiryLayouts are the date formats items use for expiry fields.
var expiryLayouts = []string{"2006-01-02", "2006-01", "01/06", "1/06", "01/2006", "1/2006", "01-06", "01-2006", "2006/01/02", "02/01/2006", "Jan 2006", "January 2006", "Jan 2, 2006", time.RFC3339}

// ParseExpiry reads an expiry date. Month-only dates expire at the end of
// that month, like a card.
func ParseExpiry(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range expiryLayouts {
		t, err := time.ParseInLocation(layout, raw, time.Local)
		if err != nil {
			continue
		}
		if !strings.Contains(layout, "02") && !strings.Contains(layout, "2,") && layout != time.RFC3339 {
			t = t.AddDate(0, 1, -1)
		}
		return t, true
	}
	return time.Time{}, false
}

func expiryFinding(it *wtItem, what string, exp, now time.Time, window int) *Finding {
	days := int(exp.Sub(now).Hours() / 24)
	if exp.Before(now) {
		days = -int(now.Sub(exp).Hours()/24) - 1
	}
	if days > window {
		return nil
	}
	date := exp.Local().Format("Jan 2, 2006")
	var f Finding
	switch {
	case days < 0:
		f = it.finding("expiring", SeverityHigh, "Expired", what+" expired on "+date+".", "renew")
	case days == 0:
		f = it.finding("expiring", SeverityMedium, "Expires today", what+" expires on "+date+".", "renew")
	default:
		sev := SeverityMedium
		if days > 30 {
			sev = SeverityLow
		}
		f = it.finding("expiring", sev, "Expires in "+itoa(days)+" "+wordFor(days, "day", "days"), what+" expires on "+date+".", "renew")
	}
	return &f
}

// liveSecrets are API keys that work as-is when found in a note.
var liveSecrets = []struct {
	name string
	re   *regexp.Regexp
}{
	{"Stripe live secret key", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}`)},
	{"AWS access key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})`)},
	{"Slack token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"OpenAI API key", regexp.MustCompile(`\bsk-(proj-)?[A-Za-z0-9_-]{32,}`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"SendGrid key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`)},
	{"private key", regexp.MustCompile(`-----BEGIN ([A-Z]+ )?PRIVATE KEY-----`)},
}

func findLiveSecret(texts ...string) string {
	for _, t := range texts {
		if t == "" {
			continue
		}
		for _, s := range liveSecrets {
			if s.re.MatchString(t) {
				return s.name
			}
		}
	}
	return ""
}

// checkItems covers the checks that look at one item at a time.
func checkItems(v *Vault, items []*wtItem, now time.Time, eligible map[string]int) []Finding {
	var out []Finding
	add := func(f *Finding) {
		if f != nil {
			out = append(out, *f)
		}
	}
	for _, it := range items {
		eligible["exposed"]++
		if it.tel.Exposed {
			fixes := []string{"change_password", "clear_exposed"}
			if it.ref.Spec.ID != "password" {
				fixes = []string{"rotate", "clear_exposed"}
			}
			f := it.finding("exposed", SeverityCritical, "Marked as exposed", "Change this secret, then clear the exposed flag.", fixes...)
			if it.site != nil {
				if f.ChangeURL = changePasswordURL(it.site); f.ChangeURL != "" {
					f.Fixes = append(f.Fixes, "open_change_url")
				}
			}
			out = append(out, f)
		}

		switch it.ref.Spec.ID {
		case "password":
			e := v.Entries[it.ref.Index]
			if it.site != nil {
				eligible["insecure_url"]++
				if it.site.Scheme == "http" && !localHost(it.site.Hostname()) {
					add(ptr(it.finding("insecure_url", SeverityMedium, "Site doesn't use HTTPS", "The saved address starts with http://, so the password could be sent unencrypted. Change it to https:// if the site supports it.", "edit_item")))
				}
				if s, ok := lookupSite(it.site.Hostname()); ok {
					if s.totp {
						eligible["no_2fa"]++
						if !loginHasTOTP(v, e, it.site.Hostname()) {
							add(ptr(it.finding("no_2fa", SeverityMedium, "Two-factor available", RegistrableDomain(it.site.Hostname())+" supports authenticator codes. Turn on two-factor there and save the setup key in this login.", "enable_2fa")))
						}
					}
					if s.passkey {
						eligible["passkey_available"]++
						if len(e.Passkeys) == 0 {
							add(ptr(it.finding("passkey_available", SeverityLow, "Passkey available", RegistrableDomain(it.site.Hostname())+" supports passkeys, which can't be phished or reused.", "add_passkey")))
						}
					}
				}
			}
			for _, cf := range e.Fields {
				if isExpiryLabel(cf.Label) {
					if t, ok := ParseExpiry(cf.Value); ok {
						eligible["expiring"]++
						add(expiryFinding(it, cf.Label, t, now, 30))
					}
				}
			}
			texts := []string{e.Notes}
			for _, cf := range e.Fields {
				texts = append(texts, cf.Value)
			}
			eligible["api_key"]++
			if name := findLiveSecret(texts...); name != "" {
				add(ptr(it.finding("api_key", SeverityMedium, "Secret in notes", "A "+name+" is saved in this login's notes or fields. Save it as its own API key item so its use is tracked.", "edit_item")))
			}
		case "note":
			eligible["api_key"]++
			if name := findLiveSecret(v.SecureNotes[it.ref.Index].Content); name != "" {
				add(ptr(it.finding("api_key", SeverityMedium, "Secret in a note", "A "+name+" is saved in this note. Save it as its own API key item so its use is tracked.", "edit_item")))
			}
		case "apikey", "token", "cloud":
			eligible["api_key"]++
			since := it.tel.LastRotation
			if since.IsZero() {
				since = it.tel.CreatedAt
			}
			if !since.IsZero() {
				if days := int(now.Sub(since).Hours() / 24); days > 365 {
					f := it.finding("api_key", SeverityLow, "Key not rotated in "+ageText(days), "Long-lived keys are more likely to have leaked somewhere. Rotate it with the provider.", "rotate")
					f.ID += ":age"
					out = append(out, f)
				}
			}
			if it.ref.Spec.ID == "cloud" {
				if t, ok := ParseExpiry(v.CloudCredentialsItems[it.ref.Index].Expiration); ok {
					eligible["expiring"]++
					add(expiryFinding(it, "This credential", t, now, 30))
				}
			}
		case "wifi":
			eligible["wifi"]++
			sec := strings.ToLower(strings.TrimSpace(v.WiFiCredentials[it.ref.Index].SecurityType))
			switch {
			case strings.Contains(sec, "wep"):
				add(ptr(it.finding("wifi", SeverityHigh, "Uses WEP", "WEP can be cracked in minutes. Switch the network to WPA2 or WPA3 in the router.", "edit_item")))
			case sec == "open" || sec == "none" || sec == "nopass" || (sec == "" && it.password == ""):
				add(ptr(it.finding("wifi", SeverityMedium, "Open network", "Anyone nearby can join and see unencrypted traffic. Turn on WPA2 or WPA3 in the router.", "edit_item")))
			}
		case "recovery":
			eligible["recovery_codes"]++
			rc := v.RecoveryCodeItems[it.ref.Index]
			total, used := len(rc.Codes), usedCodes(rc)
			switch {
			case total > 0 && used >= total:
				add(ptr(it.finding("recovery_codes", SeverityHigh, "All recovery codes used", "Make new codes with the service before you lose access to your other sign-in methods.", "renew")))
			case total > 0 && used*4 >= total*3:
				add(ptr(it.finding("recovery_codes", SeverityMedium, "Only "+itoa(total-used)+" recovery codes left", "Make new codes with the service soon.", "renew")))
			}
		case "ssh_key":
			eligible["ssh_key"]++
			add(sshKeyFinding(it, v.SSHKeys[it.ref.Index].PrivateKey))
		case "ssh_config":
			if pk := v.SSHConfigs[it.ref.Index].PrivateKey; strings.TrimSpace(pk) != "" {
				eligible["ssh_key"]++
				add(sshKeyFinding(it, pk))
			}
		case "certificate":
			eligible["certificate"]++
			c := v.Certificates[it.ref.Index]
			exp := c.Expiry
			if cert := parseCertificate(c.CertData); cert != nil {
				exp = cert.NotAfter
				add(certificateFinding(it, cert))
			}
			if !exp.IsZero() {
				eligible["expiring"]++
				add(expiryFinding(it, "This certificate", exp, now, 30))
			}
		case "banking":
			b := v.BankingItems[it.ref.Index]
			if t, ok := ParseExpiry(b.Expiry); ok {
				eligible["expiring"]++
				add(expiryFinding(it, "This card", t, now, 30))
			}
		case "document":
			if t, ok := ParseExpiry(v.Documents[it.ref.Index].Expiry); ok {
				eligible["expiring"]++
				add(expiryFinding(it, "This document", t, now, 30))
			}
		case "govid":
			g := v.GovIDs[it.ref.Index]
			if t, ok := ParseExpiry(g.Expiry); ok {
				eligible["expiring"]++
				what := "This ID"
				if strings.TrimSpace(g.Type) != "" {
					what = "This " + strings.ToLower(strings.TrimSpace(g.Type))
				}
				// Renewing a passport or ID takes months.
				add(expiryFinding(it, what, t, now, 180))
			}
		case "k8s":
			if t, ok := ParseExpiry(v.K8sSecrets[it.ref.Index].Expiration); ok {
				eligible["expiring"]++
				add(expiryFinding(it, "This secret", t, now, 30))
			}
		case "license":
			if t, ok := ParseExpiry(v.SoftwareLicenses[it.ref.Index].Expiration); ok {
				eligible["expiring"]++
				add(expiryFinding(it, "This license", t, now, 30))
			}
		}
	}
	return out
}

func ptr(f Finding) *Finding { return &f }

func isExpiryLabel(label string) bool {
	l := strings.ToLower(label)
	return strings.Contains(l, "expir") || strings.Contains(l, "valid until") || strings.Contains(l, "expires")
}

func usedCodes(rc RecoveryCodeEntry) int {
	used := map[string]bool{}
	for _, u := range rc.Used {
		used[strings.TrimSpace(u)] = true
	}
	n := 0
	for _, c := range rc.Codes {
		if used[strings.TrimSpace(c)] {
			n++
		}
	}
	return n
}

// loginHasTOTP reports whether a login has 2FA codes, in itself or in an
// Authenticator item with the same name or linked to its site.
func loginHasTOTP(v *Vault, e Entry, host string) bool {
	if strings.TrimSpace(e.TOTP) != "" {
		return true
	}
	for _, t := range v.TOTPEntries {
		if strings.EqualFold(strings.TrimSpace(t.Account), strings.TrimSpace(e.Account)) {
			return true
		}
	}
	reg := RegistrableDomain(host)
	for d := range v.TOTPDomainLinks {
		if RegistrableDomain(normalizeDomain(d)) == reg {
			return true
		}
	}
	return false
}

func sshKeyFinding(it *wtItem, pemData string) *Finding {
	pemData = strings.TrimSpace(pemData)
	if pemData == "" {
		return nil
	}
	var reasons []string
	sev := ""
	raise := func(s string) {
		if sev == "" || severityRank[s] > severityRank[sev] {
			sev = s
		}
	}
	var keyType string
	var bits int
	key, err := ssh.ParseRawPrivateKey([]byte(pemData))
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		if missing.PublicKey != nil {
			keyType = missing.PublicKey.Type()
			if ck, ok := missing.PublicKey.(ssh.CryptoPublicKey); ok {
				if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok {
					bits = rk.N.BitLen()
				}
			}
		} else if block, _ := pem.Decode([]byte(pemData)); block != nil && strings.HasPrefix(block.Type, "DSA") {
			keyType = ssh.KeyAlgoDSA
		}
	case err == nil:
		reasons = append(reasons, "has no passphrase")
		raise(SeverityLow)
		switch k := key.(type) {
		case *rsa.PrivateKey:
			keyType, bits = ssh.KeyAlgoRSA, k.N.BitLen()
		case *dsa.PrivateKey:
			keyType = ssh.KeyAlgoDSA
		}
	default:
		return nil
	}
	switch {
	case keyType == ssh.KeyAlgoDSA:
		reasons = append(reasons, "is a DSA key, which OpenSSH no longer accepts")
		raise(SeverityHigh)
	case keyType == ssh.KeyAlgoRSA && bits > 0 && bits < 2048:
		reasons = append(reasons, "is a "+itoa(bits)+"-bit RSA key, which is breakable")
		raise(SeverityHigh)
	case keyType == ssh.KeyAlgoRSA && bits > 0 && bits < 3072:
		reasons = append(reasons, "is a "+itoa(bits)+"-bit RSA key; 3072 bits or Ed25519 is recommended")
		raise(SeverityMedium)
	}
	if len(reasons) == 0 {
		return nil
	}
	title := "Weak SSH key"
	if len(reasons) == 1 && reasons[0] == "has no passphrase" {
		title = "SSH key without a passphrase"
	}
	f := it.finding("ssh_key", sev, title, "This key "+strings.Join(reasons, " and ")+". Make a new Ed25519 key and replace it on your servers.", "replace_key")
	return &f
}

func parseCertificate(data string) *x509.Certificate {
	rest := []byte(strings.TrimSpace(data))
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				return c
			}
		}
	}
	return nil
}

func certificateFinding(it *wtItem, c *x509.Certificate) *Finding {
	var reasons []string
	sev := SeverityMedium
	switch c.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		reasons = append(reasons, "is signed with MD5")
		sev = SeverityHigh
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		reasons = append(reasons, "is signed with SHA-1")
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if b := k.N.BitLen(); b < 2048 {
			reasons = append(reasons, "has a "+itoa(b)+"-bit RSA key")
			sev = SeverityHigh
		}
	case *ecdsa.PublicKey:
		if b := k.Curve.Params().BitSize; b < 256 {
			reasons = append(reasons, fmt.Sprintf("has a %d-bit EC key", b))
		}
	case *dsa.PublicKey:
		reasons = append(reasons, "uses a DSA key")
	}
	if len(reasons) == 0 {
		return nil
	}
	f := it.finding("certificate", sev, "Weak certificate", "This certificate "+strings.Join(reasons, " and ")+". Browsers and servers may reject it. Reissue it.", "renew")
	return &f
}

// setupPenalty is what each failed setup check takes off the score.
var setupPenalty = map[string]float64{
	"setup:profile":  10,
	"setup:alerts":   3,
	"setup:recovery": 8,
	"setup:autolock": 4,
	"setup:audit":    8,
	"setup:ai":       4,
}

func checkSetup(v *Vault, opt WatchtowerOptions, now time.Time) []SetupCheck {
	var out []SetupCheck
	add := func(id, label string, ok bool, detail, fix, sev string) {
		out = append(out, SetupCheck{ID: id, Label: label, OK: ok, Detail: detail, Fix: fix, severity: sev, penalty: setupPenalty[id]})
	}

	switch rank := profileRank(v); {
	case rank == 0:
		add("setup:profile", "Encryption profile", false, "The legacy profile uses weak key derivation. Switch to standard or hardened.", "settings:profile", SeverityHigh)
	case rank >= 2:
		add("setup:profile", "Encryption profile", true, "Memory-hard key derivation", "settings:profile", SeverityLow)
	default:
		add("setup:profile", "Encryption profile", true, "Standard key derivation", "settings:profile", SeverityLow)
	}

	switch {
	case v.AlertsEnabled && strings.TrimSpace(v.AlertEmail) != "":
		add("setup:alerts", "Security alerts", true, "Emails go to "+maskEmail(v.AlertEmail), "settings:alerts", SeverityLow)
	case v.AlertsEnabled:
		add("setup:alerts", "Security alerts", false, "Alerts are on but have no email address", "settings:alerts", SeverityLow)
	default:
		add("setup:alerts", "Security alerts", false, "You won't hear about failed unlocks or unusual activity", "settings:alerts", SeverityLow)
	}

	var methods []string
	unused := 0
	for i := range v.RecoveryCodeHashes {
		if i >= len(v.RecoveryCodeUsed) || !v.RecoveryCodeUsed[i] {
			unused++
		}
	}
	if unused > 0 {
		methods = append(methods, itoa(unused)+" recovery codes")
	}
	if v.RecoveryPasskeyEnabled && len(v.RecoveryPasskeyCred) > 0 {
		methods = append(methods, "recovery passkey")
	}
	if len(v.RecoveryHash) > 0 && len(v.RecoverySlot) > 0 {
		methods = append(methods, "recovery key")
	}
	if v.RecoveryShareThreshold >= 2 {
		methods = append(methods, "trustee quorum")
	}
	if len(methods) > 0 {
		add("setup:recovery", "Account recovery", true, strings.Join(methods, ", "), "settings:recovery", SeverityLow)
	} else if len(v.RecoveryCodeHashes) > 0 {
		add("setup:recovery", "Account recovery", false, "Every recovery code has been used", "settings:recovery", SeverityHigh)
	} else {
		add("setup:recovery", "Account recovery", false, "No recovery codes, recovery key or recovery passkey", "settings:recovery", SeverityHigh)
	}

	idle, max := autolockMinutes(v)
	if idle == 0 && max == 0 {
		add("setup:autolock", "Auto-lock", false, "The vault never locks by itself", "settings:autolock", SeverityMedium)
	} else {
		parts := []string{}
		if idle > 0 {
			parts = append(parts, "after "+itoa(idle)+" min idle")
		}
		if max > 0 {
			parts = append(parts, itoa(max)+" min at most")
		}
		add("setup:autolock", "Auto-lock", true, "Locks "+strings.Join(parts, ", "), "settings:autolock", SeverityLow)
	}

	switch {
	case !opt.TouchIDAvailable:
		add("setup:touchid", "Touch ID", true, "Not available on this device", "settings:touchid", SeverityLow)
	case opt.TouchIDConfigured:
		add("setup:touchid", "Touch ID", true, "Unlock with your fingerprint", "settings:touchid", SeverityLow)
	default:
		add("setup:touchid", "Touch ID", false, "Unlocking with Touch ID means typing the master password less often, where it can be seen", "settings:touchid", SeverityLow)
	}

	logs := activityAuditLogs()
	if bad := AuditIntegrity(logs); bad >= 0 {
		add("setup:audit", "Audit log", false, "Entry "+itoa(bad+1)+" doesn't match its signature", "settings:audit", SeverityCritical)
	} else {
		add("setup:audit", "Audit log", true, itoa(len(logs))+" signed entries verified", "settings:audit", SeverityLow)
	}

	writers, bypass := mcpExposure(now)
	switch {
	case bypass > 0:
		add("setup:ai", "AI assistant access", false, itoa(bypass)+" "+wordFor(bypass, "assistant changes", "assistants change")+" your vault without asking", "settings:ai", SeverityMedium)
	case writers > 3:
		add("setup:ai", "AI assistant access", false, itoa(writers)+" assistants or tokens can change items", "settings:ai", SeverityLow)
	default:
		detail := "No assistant can change items without your approval"
		if writers > 0 {
			detail = itoa(writers) + " " + wordFor(writers, "assistant", "assistants") + " can ask to change items"
		}
		add("setup:ai", "AI assistant access", true, detail, "settings:ai", SeverityLow)
	}

	if BreachEnabled(v) {
		add("setup:breach", "Breach check", true, "Passwords are checked against known breaches", "settings:breach", SeverityLow)
	} else {
		add("setup:breach", "Breach check", false, "Off. Turn it on to check passwords against known breaches without sending them", "settings:breach", SeverityLow)
	}
	return out
}

// autolockMinutes reads the shared lock policy from the vault's settings:
// the desktop app, pm and the extension use the same values.
func autolockMinutes(v *Vault) (idle, max int) {
	idle, max = 15, 60
	if v.Desktop == nil || v.Desktop.Settings == nil {
		return
	}
	read := func(key string, def int) int {
		x, ok := v.Desktop.Settings[key]
		if !ok {
			return def
		}
		switch t := x.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return n
			}
			if strings.EqualFold(strings.TrimSpace(t), "never") {
				return 0
			}
		}
		return def
	}
	return read("inactivity", idle), read("sessionTimeout", max)
}

// mcpExposure counts the paired assistants and tokens that can ask to change
// items, and the assistants whose changes skip approval right now.
var mcpExposure = func(now time.Time) (writers, bypass int) {
	canWrite := func(perms []string) bool {
		return hasPermission(perms, "add_entry") || hasPermission(perms, "edit_entry") || hasPermission(perms, "delete_entry")
	}
	if list, err := ListMCPAssistants(); err == nil {
		for _, a := range list {
			if canWrite(a.Perms) {
				writers++
			}
			if a.BypassActive(now) {
				bypass++
			}
		}
	}
	if tokens, err := ListMCPTokens(); err == nil {
		for _, t := range tokens {
			if (t.ExpiresAt.IsZero() || now.Before(t.ExpiresAt)) && canWrite(t.Permissions) {
				writers++
			}
		}
	}
	return
}
