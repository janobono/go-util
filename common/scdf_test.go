package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToDf(t *testing.T) {
	type testCase struct {
		value    string
		expected string
	}

	t.Run("ToDf", func(t *testing.T) {
		tests := []testCase{
			{value: "", expected: ""},
			{value: "  ", expected: ""},
			{value: "   ľščťžýáíéňäúô ĽŠČŤŽÝÁÍÉŇÄÚÔ   ", expected: "lsctzyaienauo LSCTZYAIENAUO"},
		}

		for _, test := range tests {
			actual := ToDf(test.value)
			assert.Equal(t, actual, test.expected)
		}
	})
}

func TestToScDf(t *testing.T) {
	type testCase struct {
		value    string
		expected string
	}

	t.Run("ToScDf", func(t *testing.T) {
		tests := []testCase{
			{value: "", expected: ""},
			{value: "  ", expected: ""},
			{value: "   ľščťžýáíéňäúô ĽŠČŤŽÝÁÍÉŇÄÚÔ   ", expected: "lsctzyaienauo lsctzyaienauo"},
		}

		for _, test := range tests {
			actual := ToScDf(test.value)
			assert.Equal(t, actual, test.expected)
		}
	})
}
