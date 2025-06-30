package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsBlank(t *testing.T) {
	type testCase struct {
		value    string
		expected bool
	}

	t.Run("IsBlank", func(t *testing.T) {
		tests := []testCase{
			{value: "", expected: true},
			{value: "  ", expected: true},
			{value: "anything", expected: false},
		}

		for _, test := range tests {
			actual := IsBlank(test.value)
			assert.Equal(t, actual, test.expected)
		}
	})
}

func TestNotBlank(t *testing.T) {
	type testCase struct {
		value    string
		expected bool
	}

	t.Run("NotBlank", func(t *testing.T) {
		tests := []testCase{
			{value: "", expected: false},
			{value: "  ", expected: false},
			{value: "anything", expected: true},
		}

		for _, test := range tests {
			actual := NotBlank(test.value)
			assert.Equal(t, actual, test.expected)
		}
	})
}

func TestSplitWithoutBlank(t *testing.T) {
	type testCase struct {
		name      string
		value     string
		separator string
		expected  []string
	}

	tests := []testCase{
		{name: "Empty input", value: "", separator: " ", expected: []string{}},
		{name: "Only spaces", value: "   ", separator: " ", expected: []string{}},
		{name: "Simple comma split", value: "a,b,c", separator: ",", expected: []string{"a", "b", "c"}},
		{name: "Spaces with comma", value: " a , b , c ", separator: ",", expected: []string{"a", "b", "c"}},
		{name: "Empty between commas", value: " a ,, c ", separator: ",", expected: []string{"a", "c"}},
		{name: "Pipe with empty", value: "one|two| |three|", separator: "|", expected: []string{"one", "two", "three"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := SplitWithoutBlank(test.value, test.separator)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestDeduplicate(t *testing.T) {
	type testCase struct {
		name     string
		input    []string
		expected []string
	}

	tests := []testCase{
		{
			name:     "No duplicates",
			input:    []string{"apple", "banana", "cherry"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "With duplicates",
			input:    []string{"apple", "banana", "apple", "cherry", "banana"},
			expected: []string{"apple", "banana", "cherry"},
		},
		{
			name:     "All duplicates",
			input:    []string{"apple", "apple", "apple"},
			expected: []string{"apple"},
		},
		{
			name:     "Empty input",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "Case-sensitive",
			input:    []string{"apple", "Apple", "APPLE"},
			expected: []string{"apple", "Apple", "APPLE"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := Deduplicate(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsValidEmail(t *testing.T) {
	type testCase struct {
		value    string
		expected bool
	}

	t.Run("IsValidEmail", func(t *testing.T) {
		tests := []testCase{
			{value: "", expected: false},
			{value: "  ", expected: false},
			{value: "anything", expected: false},
			{value: "anything@domain", expected: false},
			{value: "anything@domain.sk", expected: true},
		}

		for _, test := range tests {
			actual := IsValidEmail(test.value)
			assert.Equal(t, actual, test.expected)
		}
	})
}
