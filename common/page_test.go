package common

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestTotalPages(t *testing.T) {
	type testCase struct {
		pageSize  int32
		totalRows int64
		expected  int32
	}

	t.Run("TotalPages", func(t *testing.T) {
		tests := []testCase{
			{0, 0, 0},
			{20, 0, 0},
			{0, 10, 0},
			{20, 10, 1},
			{20, 20, 1},
			{20, 21, 2},
			{math.MaxInt32, math.MaxInt64, TotalPages(math.MaxInt32, math.MaxInt64)},
		}

		for _, test := range tests {
			actual := TotalPages(test.pageSize, test.totalRows)
			assert.Equal(t, actual, test.expected)
		}
	})
}
