package common

import (
	"testing"
)

func TestNewPageable_DefaultsApplied(t *testing.T) {
	p := NewPageable(-1, -10, "", "id ASC")

	if p.Page != 0 {
		t.Errorf("Expected page 0, got %d", p.Page)
	}
	if p.Size != 20 {
		t.Errorf("Expected size 20, got %d", p.Size)
	}
	if p.Sort != "id ASC" {
		t.Errorf("Expected sort 'id ASC', got '%s'", p.Sort)
	}
}

func TestPageable_OffsetAndLimit(t *testing.T) {
	p := NewPageable(2, 10, "name DESC", "id ASC")

	if p.Offset() != 20 {
		t.Errorf("Expected offset 20, got %d", p.Offset())
	}
	if p.Limit() != 10 {
		t.Errorf("Expected limit 10, got %d", p.Limit())
	}
}

func TestPageable_TotalPages(t *testing.T) {
	tests := []struct {
		totalElements int64
		pageSize      int32
		expected      int32
	}{
		{0, 10, 0},
		{5, 10, 1},
		{10, 10, 1},
		{15, 10, 2},
		{21, 10, 3},
	}

	for _, test := range tests {
		p := NewPageable(0, test.pageSize, "", "id ASC")
		got := p.TotalPages(test.totalElements)

		if got != test.expected {
			t.Errorf("TotalPages(%d elements, size %d): expected %d, got %d",
				test.totalElements, test.pageSize, test.expected, got)
		}
	}
}

func TestNewPage(t *testing.T) {
	pageable := NewPageable(0, 10, "", "id ASC")
	content := []string{"a", "b", "c"}

	page := NewPage(pageable, 3, content)

	if page.TotalElements != 3 {
		t.Errorf("Expected TotalElements = 3, got %d", page.TotalElements)
	}
	if page.TotalPages != 1 {
		t.Errorf("Expected TotalPages = 1, got %d", page.TotalPages)
	}
	if !page.First {
		t.Errorf("Expected First = true")
	}
	if !page.Last {
		t.Errorf("Expected Last = true")
	}
	if page.Empty {
		t.Errorf("Expected Empty = false")
	}
}
