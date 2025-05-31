package db

import (
	"testing"
)

func TestNewUUID(t *testing.T) {
	id := NewUUID()

	t.Log(id.String())

	id, err := ParseUUID(id.String())

	if err != nil {
		t.Fatal(err)
	}

	t.Log(id.String())
}
