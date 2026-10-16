package apm

import (
	_ "embed"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// Password strength estimates how many guesses an attacker who knows the
// usual tricks needs: common passwords and words, l33t spellings, keyboard
// runs, sequences, repeats, dates and the account's own name. It splits the
// password into the cheapest set of such patterns and counts the guesses for
// each, the way zxcvbn does, in a much smaller form.

//go:embed watchtower_data/common_passwords.txt
var commonPasswordsRaw string

var (
	commonOnce  sync.Once
	commonRanks map[string]int
)

func commonPasswords() map[string]int {
	commonOnce.Do(func() {
		lines := strings.Split(commonPasswordsRaw, "\n")
		commonRanks = make(map[string]int, len(lines))
		for i, l := range lines {
			l = strings.ToLower(strings.TrimSpace(l))
			if l == "" {
				continue
			}
			if _, ok := commonRanks[l]; !ok {
				commonRanks[l] = i + 1
			}
		}
	})
	return commonRanks
}

// StrengthResult is a password's estimated strength.
type StrengthResult struct {
	Bits    float64
	Common  bool
	Short   bool
	Reasons []string
}

// Weak is the line Watchtower draws: a common password, or one an attacker
// guesses quickly. The extension's weak badge uses the same rule.
func (s StrengthResult) Weak() bool {
	return s.Common || s.Bits < 28 || (s.Short && s.Bits < 40)
}

const (
	reasonCommonWord = "a common word"
	reasonUserInput  = "the account or site name"
	reasonSequence   = "a sequence like abc or 123"
	reasonRepeat     = "repeated characters"
	reasonKeyboard   = "a keyboard pattern"
	reasonDate       = "a date or year"
)

type strengthMatch struct {
	i, j    int
	guesses float64
	reason  string
}

var leetMap = map[rune]rune{'4': 'a', '@': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g', '1': 'i', '!': 'i', '|': 'l', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't', '2': 'z'}

func unleet(r rune) rune {
	if m, ok := leetMap[r]; ok {
		return m
	}
	return unicode.ToLower(r)
}

func charCardinality(r rune) float64 {
	switch {
	case r >= '0' && r <= '9':
		return 10
	case r >= 'a' && r <= 'z':
		return 26
	case r >= 'A' && r <= 'Z':
		return 26
	case r < 128:
		return 33
	}
	return 100
}

// PasswordStrength estimates pw's strength. inputs are words an attacker
// would try first, such as the username and the site name.
func PasswordStrength(pw string, inputs ...string) StrengthResult {
	runes := []rune(pw)
	if len(runes) > 64 {
		runes = runes[:64]
	}
	n := len(runes)
	res := StrengthResult{Short: n < 8}
	if n == 0 {
		return res
	}
	lower := make([]rune, n)
	plain := make([]rune, n)
	for i, r := range runes {
		lower[i] = unicode.ToLower(r)
		plain[i] = unleet(r)
	}
	common := commonPasswords()
	if _, ok := common[string(lower)]; ok {
		res.Common = true
	} else if _, ok := common[string(plain)]; ok {
		res.Common = true
	}

	words := map[string]bool{}
	for _, in := range inputs {
		for _, w := range strings.FieldsFunc(strings.ToLower(in), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			if len([]rune(w)) >= 3 {
				words[w] = true
			}
		}
	}

	var matches []strengthMatch
	for i := 0; i < n; i++ {
		for j := i + 3; j <= n && j-i <= 24; j++ {
			raw, sub := string(lower[i:j]), string(plain[i:j])
			caseMul := caseVariations(runes[i:j])
			if words[raw] || words[sub] {
				matches = append(matches, strengthMatch{i, j, 20 * caseMul, reasonUserInput})
			}
			if j-i < 4 && !(i == 0 && j == n) {
				continue
			}
			rank, ok := common[raw]
			mul := caseMul
			if !ok {
				rank, ok = common[sub]
				mul *= 2
			}
			if ok {
				matches = append(matches, strengthMatch{i, j, math.Max(float64(rank), 10) * mul, reasonCommonWord})
			}
		}
	}
	matches = append(matches, sequenceMatches(lower)...)
	matches = append(matches, repeatMatches(runes)...)
	matches = append(matches, keyboardMatches(lower)...)
	matches = append(matches, dateMatches(runes)...)

	// best[j] is the fewest bits to cover runes[:j].
	best := make([]float64, n+1)
	via := make([]int, n+1)
	for j := 1; j <= n; j++ {
		best[j] = best[j-1] + math.Log2(charCardinality(runes[j-1]))
		via[j] = -1
		for k, m := range matches {
			if m.j != j {
				continue
			}
			cost := best[m.i] + math.Log2(math.Max(m.guesses, 1))
			if m.i > 0 {
				cost++
			}
			if cost < best[j] {
				best[j] = cost
				via[j] = k
			}
		}
	}
	res.Bits = best[n]
	seen := map[string]bool{}
	for j := n; j > 0; {
		if k := via[j]; k >= 0 {
			if r := matches[k].reason; !seen[r] {
				seen[r] = true
				res.Reasons = append(res.Reasons, r)
			}
			j = matches[k].i
		} else {
			j--
		}
	}
	sort.Strings(res.Reasons)
	return res
}

func caseVariations(r []rune) float64 {
	upper, lowerCount := 0, 0
	for _, c := range r {
		if unicode.IsUpper(c) {
			upper++
		} else if unicode.IsLower(c) {
			lowerCount++
		}
	}
	switch {
	case upper == 0:
		return 1
	case lowerCount == 0 || (upper == 1 && unicode.IsUpper(r[0])):
		return 2
	}
	return math.Pow(2, math.Min(float64(upper), 6))
}

func sequenceMatches(r []rune) []strengthMatch {
	var out []strengthMatch
	n := len(r)
	for i := 0; i < n-2; {
		d := r[i+1] - r[i]
		if (d != 1 && d != -1) || !sameClass(r[i], r[i+1]) {
			i++
			continue
		}
		j := i + 1
		for j+1 < n && r[j+1]-r[j] == d && sameClass(r[j], r[j+1]) {
			j++
		}
		if j-i+1 >= 3 {
			base := 26.0
			if unicode.IsDigit(r[i]) {
				base = 10
			}
			if r[i] == 'a' || r[i] == '1' || r[i] == '0' || r[i] == 'z' || r[i] == '9' {
				base = 4
			}
			g := base * float64(j-i+1)
			if d < 0 {
				g *= 2
			}
			out = append(out, strengthMatch{i, j + 1, g, reasonSequence})
		}
		i = j
	}
	return out
}

func sameClass(a, b rune) bool {
	return (unicode.IsDigit(a) && unicode.IsDigit(b)) || (unicode.IsLetter(a) && unicode.IsLetter(b))
}

func repeatMatches(r []rune) []strengthMatch {
	var out []strengthMatch
	n := len(r)
	for i := 0; i < n; i++ {
		for p := 1; p <= 8 && i+2*p <= n; p++ {
			k := 1
			for i+(k+1)*p <= n && string(r[i+k*p:i+(k+1)*p]) == string(r[i:i+p]) {
				k++
			}
			if k < 2 || k*p < 3 {
				continue
			}
			block := 1.0
			for _, c := range r[i : i+p] {
				block *= charCardinality(c)
			}
			block = math.Min(block, 1e6)
			out = append(out, strengthMatch{i, i + k*p, block * float64(k), reasonRepeat})
		}
	}
	return out
}

var keyboardRows = []string{"`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"}
var shiftedKeys = map[rune]rune{'~': '`', '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8', '(': '9', ')': '0', '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\', ':': ';', '"': '\'', '<': ',', '>': '.', '?': '/'}

type keyPos struct{ row, col int }

var keyPositions = func() map[rune]keyPos {
	m := map[rune]keyPos{}
	for ri, row := range keyboardRows {
		for ci, c := range row {
			m[c] = keyPos{ri, ci}
		}
	}
	return m
}()

func keyAdjacent(a, b rune) bool {
	if s, ok := shiftedKeys[a]; ok {
		a = s
	}
	if s, ok := shiftedKeys[b]; ok {
		b = s
	}
	pa, ok1 := keyPositions[a]
	pb, ok2 := keyPositions[b]
	if !ok1 || !ok2 || a == b {
		return false
	}
	dr, dc := pb.row-pa.row, pb.col-pa.col
	// Rows are offset, so a key touches the two keys below it at the same
	// column and one to the left.
	switch dr {
	case 0:
		return dc == 1 || dc == -1
	case 1:
		return dc == 0 || dc == -1
	case -1:
		return dc == 0 || dc == 1
	}
	return false
}

func keyboardMatches(r []rune) []strengthMatch {
	var out []strengthMatch
	n := len(r)
	for i := 0; i < n-3; {
		j := i
		turns := 0
		lastDir := keyPos{}
		for j+1 < n && keyAdjacent(r[j], r[j+1]) {
			a, b := keyPositions[r[j]], keyPositions[r[j+1]]
			dir := keyPos{b.row - a.row, b.col - a.col}
			if j > i && dir != lastDir {
				turns++
			}
			lastDir = dir
			j++
		}
		if j-i+1 >= 4 {
			g := 50 * math.Pow(2, float64(j-i)) * math.Pow(4, float64(turns))
			out = append(out, strengthMatch{i, j + 1, g, reasonKeyboard})
			i = j + 1
			continue
		}
		i++
	}
	return out
}

var dateLike = regexp.MustCompile(`^(\d{1,4})[-/._ ]?(\d{1,2})[-/._ ]?(\d{1,4})$`)

func dateMatches(r []rune) []strengthMatch {
	var out []strengthMatch
	n := len(r)
	for i := 0; i+4 <= n; i++ {
		s := string(r[i : i+4])
		if y, err := strconv.Atoi(s); err == nil && y >= 1900 && y <= 2099 {
			out = append(out, strengthMatch{i, i + 4, 150, reasonDate})
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 6; j <= n && j-i <= 10; j++ {
			if plausibleDate(string(r[i:j])) {
				out = append(out, strengthMatch{i, j, 365 * 130, reasonDate})
			}
		}
	}
	return out
}

func plausibleDate(s string) bool {
	digits := 0
	for _, c := range s {
		if unicode.IsDigit(c) {
			digits++
		}
	}
	if digits != 6 && digits != 8 {
		return false
	}
	m := dateLike.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	day := func(x int) bool { return x >= 1 && x <= 31 }
	month := func(x int) bool { return x >= 1 && x <= 12 }
	switch {
	case len(m[1]) == 4:
		return month(b) && day(c)
	case len(m[3]) == 4 || len(m[3]) == 2:
		return (day(a) && month(b)) || (month(a) && day(b))
	}
	return false
}
