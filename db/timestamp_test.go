package db

import (
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	timestamp := NowUTC()

	t.Log(timestamp)

	timestamp = TimestampUTC(time.Now())

	t.Log(timestamp)

	s, _ := TimestampToStringUTC(&timestamp)

	t.Log(s)

	timestamp, _ = ParseTimestampUTC(s)

	t.Log(timestamp)
}
