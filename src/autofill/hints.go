package autofill

import (
	"regexp"
	"strings"
)

var emailRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)

func extractEmailHints(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, item := range items {
		for _, match := range emailRegex.FindAllString(strings.ToLower(item), -1) {
			match = strings.TrimSpace(match)
			if match == "" {
				continue
			}
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			out = append(out, match)
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

func extractDomainHints(items []string) []string {
	seen := map[string]struct{}{}
	high := make([]string, 0, 4)
	low := make([]string, 0, 4)

	add := func(dst *[]string, domain string) {
		if domain == "" {
			return
		}
		if _, ok := seen[domain]; ok {
			return
		}
		seen[domain] = struct{}{}
		*dst = append(*dst, domain)
	}

	for _, item := range items {
		text := strings.ToLower(strings.TrimSpace(item))
		if text == "" {
			continue
		}

		candidates := []string{text}
		candidates = append(candidates, strings.FieldsFunc(text, func(r rune) bool {
			switch r {
			case ' ', '\t', '\n', '\r', ',', ';', '(', ')', '[', ']', '{', '}', '"', '\'':
				return true
			default:
				return false
			}
		})...)

		for _, c := range candidates {
			c = strings.TrimSpace(c)
			if c == "" || strings.Contains(c, "@") {
				continue
			}
			domain := inferDomain(c)
			if domain == "" {
				continue
			}
			if strings.Contains(c, "://") || strings.Contains(c, "/") {
				add(&high, domain)
			} else {
				add(&low, domain)
			}
		}
	}

	out := make([]string, 0, len(high)+len(low))
	out = append(out, high...)
	out = append(out, low...)
	if len(out) > 6 {
		return out[:6]
	}
	return out
}
