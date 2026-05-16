//go:build !nativeget

package get

import (
	"strings"
)

func RankMatch(query, target string) int {
	if query == "" {
		return 1
	}
	q := strings.ToLower(query)
	t := strings.ToLower(target)

	if q == t {
		return 1000
	}

	terms := strings.Fields(q)
	totalScore := 0
	foundAll := true

	for _, term := range terms {
		termScore := 0
		if term == t {
			term_score := 500
			termScore = term_score
		} else if strings.HasPrefix(t, term) {
			termScore = 200
		} else if strings.Contains(t, term) {
			termScore = 100
		} else {
			qi := 0
			ti := 0
			matchCount := 0
			for qi < len(term) && ti < len(t) {
				if term[qi] == t[ti] {
					matchCount++
					qi++
				}
				ti++
			}
			if matchCount == len(term) {
				termScore = 50
			} else {
				foundAll = false
				break
			}
		}
		totalScore += termScore
	}

	if !foundAll {
		return 0
	}

	return totalScore
}

var cachedTargets []string

func LoadTargets(targets []string) {
	cachedTargets = targets
}

func SearchSorted(query string, topN int) []int {
	// Simplified stub search
	type scored struct {
		idx   int
		score int
	}
	var results []scored
	for i, t := range cachedTargets {
		score := RankMatch(query, t)
		if score > 0 {
			results = append(results, scored{i, score})
		}
	}
	// (Omitted sorting in stub for simplicity, just returning first topN)
	if len(results) > topN {
		results = results[:topN]
	}
	out := make([]int, len(results))
	for i, r := range results {
		out[i] = r.idx
	}
	return out
}

func LoadVaultJSON(jsonStr string) int {
	return 0
}
