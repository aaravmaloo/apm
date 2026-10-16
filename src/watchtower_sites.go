package apm

import (
	_ "embed"
	"net"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// The site directory lists sites that support authenticator codes (from
// 2fa.directory) and passkeys (from passkeys.directory). It is a snapshot
// refreshed by scripts/update_site_directories.go.

//go:embed watchtower_data/sites.txt
var siteDirectoryRaw string

type siteSupport struct {
	totp    bool
	passkey bool
}

var (
	siteOnce sync.Once
	siteDir  map[string]siteSupport
)

func siteDirectory() map[string]siteSupport {
	siteOnce.Do(func() {
		siteDir = map[string]siteSupport{}
		for _, line := range strings.Split(siteDirectoryRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			domain, flags, _ := strings.Cut(line, " ")
			siteDir[domain] = siteSupport{totp: strings.Contains(flags, "t"), passkey: strings.Contains(flags, "p")}
		}
	})
	return siteDir
}

// siteURL parses a stored website, adding https:// when there is no scheme.
func siteURL(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return nil, false
	}
	return u, true
}

// RegistrableDomain is the part of a host a person registers, like
// github.com for gist.github.com.
func RegistrableDomain(host string) string {
	host = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "www.")
	if host == "" || net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

func lookupSite(host string) (siteSupport, bool) {
	dir := siteDirectory()
	if s, ok := dir[RegistrableDomain(host)]; ok {
		return s, true
	}
	return siteSupport{}, false
}

// localHost reports hosts where plain http is expected: loopback, private
// addresses and .local names.
func localHost(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return !strings.Contains(host, ".")
}

// changePasswordURL is the site's well-known change-password page.
func changePasswordURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := u.Scheme
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + u.Host + "/.well-known/change-password"
}
