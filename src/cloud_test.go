package apm

import (
	"testing"
)

func TestExtractFileID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Raw ID",
			input:    "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
		{
			name:     "Standard View Link",
			input:    "https://drive.google.com/file/d/100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ/view?usp=sharing",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
		{
			name:     "Link with query params",
			input:    "https://drive.google.com/file/d/100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ?usp=sharing",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
		{
			name:     "Export Link format",
			input:    "https://drive.google.com/uc?id=100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ&export=download",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
		{
			name:     "Export Link format simple",
			input:    "https://drive.google.com/uc?export=download&id=100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
		{
			name:     "Empty Input",
			input:    "",
			expected: "",
		},
		{
			name:     "No ID found",
			input:    "https://google.com",
			expected: "https://google.com",
		},
		{
			name:     "Complex Drive Link",
			input:    "https://drive.google.com/open?id=100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ&authuser=0",
			expected: "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractFileID(tt.input)
			if got != tt.expected {
				t.Errorf("ExtractFileID(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHashKey(t *testing.T) {
	key := "test-key"
	hashed := HashKey(key)
	if len(hashed) != 64 { // SHA256 hex is 64 chars
		t.Errorf("Expected hash length 64, got %d", len(hashed))
	}

	hashed2 := HashKey(key)
	if hashed != hashed2 {
		t.Error("Hash output not deterministic")
	}

	different := HashKey("different-key")
	if hashed == different {
		t.Error("Hashing different keys produced same output")
	}
}

func TestGenerateRetrievalKey(t *testing.T) {
	key, err := GenerateRetrievalKey()
	if err != nil {
		t.Fatalf("GenerateRetrievalKey failed: %v", err)
	}
	if key == "" {
		t.Error("Generated key is empty")
	}

	// Default GenerateRandomWords returns 2 words concatenated
	if len(key) < 6 { // Arbitrary minimum for 2 words
		t.Errorf("Generated key too short: %s", key)
	}
}
