package apm

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The breach check is opt-in. It asks the Have I Been Pwned "Pwned Passwords"
// range API about each password with k-anonymity: only the first 5 characters
// of the password's SHA-1 leave the device, and the reply is padded so its
// size says nothing either. The full hash stays inside the encrypted vault, so
// an unchanged password is not asked about again for a week.

var hibpRangeURL = "https://api.pwnedpasswords.com/range/"

var hibpClient = &http.Client{Timeout: 10 * time.Second}

const breachRecheck = 7 * 24 * time.Hour

// ErrBreachCheckOff is returned when the breach check runs while it is off.
var ErrBreachCheckOff = errors.New("the breach check is off. Turn it on with 'pm watchtower breach on'")

type BreachState struct {
	Enabled     bool                        `json:"enabled,omitempty"`
	LastChecked time.Time                   `json:"last_checked,omitzero"`
	Cache       map[string]BreachCacheEntry `json:"cache,omitempty"`
}

// BreachCacheEntry is one password's last answer, keyed by item id. SHA1 is
// the password's full hash, so a changed password is checked again.
type BreachCacheEntry struct {
	SHA1    string    `json:"sha1"`
	Count   int       `json:"count"`
	Checked time.Time `json:"checked"`
}

// BreachEnabled reports whether the opt-in breach check is on.
func BreachEnabled(v *Vault) bool {
	return v != nil && v.Watchtower != nil && v.Watchtower.Breach.Enabled
}

// SetBreachCheck turns the breach check on or off. Turning it off forgets
// every cached answer.
func SetBreachCheck(v *Vault, on bool) {
	w := v.watchtower()
	w.Breach.Enabled = on
	if !on {
		w.Breach.Cache = nil
		w.Breach.LastChecked = time.Time{}
	}
}

func passwordSHA1(pw string) string {
	sum := sha1.Sum([]byte(pw))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// BreachRun is what one breach check did.
type BreachRun struct {
	Checked int
	Cached  int
	Found   int
	Failed  int
}

// BreachPlan is a breach check split so the network part can run without
// holding the vault: PlanBreachCheck reads the vault, Run asks HIBP and Apply
// writes the answers back.
type BreachPlan struct {
	now      time.Time
	byPrefix map[string][]breachPending
	present  map[string]bool
	cached   int
	results  map[string]map[string]int
	err      error
}

type breachPending struct {
	id   string
	hash string
}

// PlanBreachCheck lists the passwords that changed or weren't checked in the
// last week. It needs the check to be on.
func PlanBreachCheck(v *Vault) (*BreachPlan, error) {
	if !BreachEnabled(v) {
		return nil, ErrBreachCheckOff
	}
	p := &BreachPlan{now: watchNow(), byPrefix: map[string][]breachPending{}, present: map[string]bool{}}
	cache := v.Watchtower.Breach.Cache
	for _, it := range watchtowerItems(v) {
		if it.password == "" {
			continue
		}
		p.present[it.ref.ID] = true
		hash := passwordSHA1(it.password)
		if c, ok := cache[it.ref.ID]; ok && c.SHA1 == hash && p.now.Sub(c.Checked) < breachRecheck {
			p.cached++
			continue
		}
		p.byPrefix[hash[:5]] = append(p.byPrefix[hash[:5]], breachPending{it.ref.ID, hash})
	}
	return p, nil
}

// Run asks HIBP about each hash prefix, a few at a time.
func (p *BreachPlan) Run(ctx context.Context) {
	p.results = make(map[string]map[string]int, len(p.byPrefix))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for prefix := range p.byPrefix {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			counts, err := hibpRange(ctx, prefix)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if p.err == nil {
					p.err = err
				}
				return
			}
			p.results[prefix] = counts
		}(prefix)
	}
	wg.Wait()
}

// Apply stores the answers in the vault. Network errors skip the passwords
// they affect; the error is returned only when nothing could be checked.
func (p *BreachPlan) Apply(v *Vault) (BreachRun, error) {
	run := BreachRun{Cached: p.cached}
	w := v.watchtower()
	if w.Breach.Cache == nil {
		w.Breach.Cache = map[string]BreachCacheEntry{}
	}
	for id := range w.Breach.Cache {
		if !p.present[id] {
			delete(w.Breach.Cache, id)
		}
	}
	for prefix, list := range p.byPrefix {
		counts, ok := p.results[prefix]
		for _, item := range list {
			if !ok {
				run.Failed++
				continue
			}
			w.Breach.Cache[item.id] = BreachCacheEntry{SHA1: item.hash, Count: counts[item.hash[5:]], Checked: p.now}
			run.Checked++
		}
	}
	for _, c := range w.Breach.Cache {
		if c.Count > 0 {
			run.Found++
		}
	}
	if run.Checked > 0 || run.Failed == 0 {
		w.Breach.LastChecked = p.now
	}
	if run.Failed > 0 && run.Checked == 0 {
		return run, fmt.Errorf("could not reach the breach service: %v", p.err)
	}
	return run, nil
}

// RunBreachCheck plans, runs and applies a breach check in one go.
func RunBreachCheck(ctx context.Context, v *Vault) (BreachRun, error) {
	p, err := PlanBreachCheck(v)
	if err != nil {
		return BreachRun{}, err
	}
	p.Run(ctx)
	return p.Apply(v)
}

func hibpRange(ctx context.Context, prefix string) (map[string]int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hibpRangeURL+prefix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "APM-Watchtower")
	resp, err := hibpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("breach service answered %s", resp.Status)
	}
	out := map[string]int{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		suffix, count, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(count))
		if err != nil || n <= 0 {
			continue
		}
		out[strings.ToUpper(strings.TrimSpace(suffix))] = n
	}
	return out, sc.Err()
}

// breachCount is the cached breach count for an item's current password, and
// whether the cache has an answer for it.
func breachCount(v *Vault, itemID, pw string) (int, bool) {
	if !BreachEnabled(v) || pw == "" {
		return 0, false
	}
	c, ok := v.Watchtower.Breach.Cache[itemID]
	if !ok || c.SHA1 != passwordSHA1(pw) {
		return 0, false
	}
	return c.Count, true
}

// BreachCheckDue reports whether the breach check is on and hasn't run in a week.
func BreachCheckDue(v *Vault) bool {
	return BreachEnabled(v) && watchNow().Sub(v.Watchtower.Breach.LastChecked) >= breachRecheck
}
