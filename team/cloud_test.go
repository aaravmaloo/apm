package main

import (
	apm "password-manager/src"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := apm.ExtractFileID(tt.input)
			if got != tt.expected {
				t.Errorf("ExtractFileID(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
