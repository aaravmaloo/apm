package apm

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"
)

type VocabWord struct {
	Score     int `json:"score"`
	Seen      int `json:"seen"`
	Accepted  int `json:"accepted"`
	Dismissed int `json:"dismissed"`
}

type NoteVocabulary struct {
	Words     map[string]VocabWord `json:"words"`
	Aliases   map[string]string    `json:"aliases"`
	UpdatedAt time.Time            `json:"updated_at,omitempty"`
}

func defaultNoteVocabulary() NoteVocabulary {
	return NoteVocabulary{
		Words:   map[string]VocabWord{},
		Aliases: map[string]string{},
	}
}

func normalizeVocabWord(word string) string {
	word = strings.TrimSpace(strings.ToLower(word))
	if len(word) > 64 {
		word = word[:64]
	}
	return word
}

func tokenizeVocabularyText(text string) []string {
	out := make([]string, 0, 64)
	var current []rune

	flush := func() {
		if len(current) == 0 {
			return
		}
		token := normalizeVocabWord(string(current))
		if token != "" {
			out = append(out, token)
		}
		current = current[:0]
	}

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '\'' {
			current = append(current, r)
			continue
		}
		flush()
	}
	flush()
	return out
}

func (v *Vault) LoadNoteVocabulary() (NoteVocabulary, error) {
	if len(v.VocabCompressed) == 0 {
		return defaultNoteVocabulary(), nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(v.VocabCompressed))
	if err != nil {
		return defaultNoteVocabulary(), err
	}
	defer reader.Close()

	decoded := defaultNoteVocabulary()
	if err := json.NewDecoder(reader).Decode(&decoded); err != nil {
		return defaultNoteVocabulary(), err
	}
	if decoded.Words == nil {
		decoded.Words = map[string]VocabWord{}
	}
	if decoded.Aliases == nil {
		decoded.Aliases = map[string]string{}
	}
	return decoded, nil
}

func (v *Vault) SaveNoteVocabulary(vocab NoteVocabulary) error {
	if vocab.Words == nil {
		vocab.Words = map[string]VocabWord{}
	}
	if vocab.Aliases == nil {
		vocab.Aliases = map[string]string{}
	}
	vocab.UpdatedAt = time.Now().UTC()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(vocab); err != nil {
		_ = gz.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	v.VocabCompressed = buf.Bytes()
	return nil
}

func (v *Vault) ReindexNoteVocabulary(ignore IgnoreConfig) error {
	current, err := v.LoadNoteVocabulary()
	if err != nil {
		current = defaultNoteVocabulary()
	}

	counts := make(map[string]int)
	for _, note := range v.SecureNotes {
		for _, token := range tokenizeVocabularyText(note.Content) {
			if ignore.ShouldIgnoreVocabWord(token) {
				continue
			}
			counts[token]++
		}
	}

	next := defaultNoteVocabulary()
	next.Aliases = current.Aliases
	for word, count := range counts {
		prev := current.Words[word]
		prev.Seen = count
		if prev.Score < count {
			prev.Score = count
		}
		next.Words[word] = prev
	}
	for word, prev := range current.Words {
		if _, exists := next.Words[word]; exists {
			continue
		}
		next.Words[word] = prev
	}

	return v.SaveNoteVocabulary(next)
}

func (v *Vault) SuggestNoteWords(prefix string, limit int, ignore IgnoreConfig) ([]string, error) {
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		return nil, err
	}

	prefix = normalizeVocabWord(prefix)
	if prefix == "" {
		return nil, nil
	}

	type candidate struct {
		Word  string
		Score int
	}
	candidates := make([]candidate, 0, 16)
	for word, stats := range vocab.Words {
		if ignore.ShouldIgnoreVocabWord(word) {
			continue
		}
		if word == prefix {
			continue
		}
		if strings.HasPrefix(word, prefix) {
			candidates = append(candidates, candidate{Word: word, Score: stats.Score})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].Word < candidates[j].Word
		}
		return candidates[i].Score > candidates[j].Score
	})
	if limit <= 0 {
		limit = 5
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.Word)
	}
	return out, nil
}

func (v *Vault) RecordNoteSuggestionFeedback(word string, accepted bool) error {
	word = normalizeVocabWord(word)
	if word == "" {
		return nil
	}
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		vocab = defaultNoteVocabulary()
	}
	stats := vocab.Words[word]
	if accepted {
		stats.Accepted++
		stats.Score += 3
	} else {
		stats.Dismissed++
		if stats.Score > 0 {
			stats.Score--
		}
	}
	vocab.Words[word] = stats
	return v.SaveNoteVocabulary(vocab)
}

func (v *Vault) UpsertVocabAlias(alias, value string) error {
	alias = normalizeVocabWord(alias)
	value = strings.TrimSpace(value)
	if alias == "" || value == "" {
		return nil
	}

	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		vocab = defaultNoteVocabulary()
	}
	vocab.Aliases[alias] = value
	return v.SaveNoteVocabulary(vocab)
}

func (v *Vault) DeleteVocabAlias(alias string) error {
	alias = normalizeVocabWord(alias)
	if alias == "" {
		return nil
	}
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		vocab = defaultNoteVocabulary()
	}
	delete(vocab.Aliases, alias)
	return v.SaveNoteVocabulary(vocab)
}

func (v *Vault) ResolveVocabAlias(alias string) (string, bool) {
	alias = normalizeVocabWord(alias)
	if alias == "" {
		return "", false
	}
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		return "", false
	}
	value, ok := vocab.Aliases[alias]
	return value, ok
}

func (v *Vault) ListVocabWords() (map[string]VocabWord, error) {
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		return nil, err
	}
	return vocab.Words, nil
}

func (v *Vault) ListVocabAliases() (map[string]string, error) {
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		return nil, err
	}
	return vocab.Aliases, nil
}

func (v *Vault) AdjustVocabWordScore(word string, delta int) error {
	word = normalizeVocabWord(word)
	if word == "" {
		return nil
	}
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		vocab = defaultNoteVocabulary()
	}
	stats := vocab.Words[word]
	stats.Score += delta
	if stats.Score < 0 {
		stats.Score = 0
	}
	vocab.Words[word] = stats
	return v.SaveNoteVocabulary(vocab)
}

func (v *Vault) DeleteVocabWord(word string) error {
	word = normalizeVocabWord(word)
	if word == "" {
		return nil
	}
	vocab, err := v.LoadNoteVocabulary()
	if err != nil {
		vocab = defaultNoteVocabulary()
	}
	delete(vocab.Words, word)
	return v.SaveNoteVocabulary(vocab)
}
