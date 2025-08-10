package db

import (
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func NowUTC() pgtype.Timestamptz {
	return TimestampUTC(time.Now().UTC())
}

func TimestampUTC(t time.Time) pgtype.Timestamptz {
	result := pgtype.Timestamptz{}
	err := result.Scan(t.UTC().Truncate(time.Second))
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func TimestampToStringUTC(ts *pgtype.Timestamptz) (string, error) {
	if ts == nil || ts.Time.IsZero() || ts.Valid == false {
		return "", fmt.Errorf("invalid or nil timestamptz")
	}
	return ts.Time.UTC().Format(time.RFC3339), nil
}

func ParseTimestampUTC(value string) (pgtype.Timestamptz, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return pgtype.Timestamptz{}, fmt.Errorf("invalid timestamp format: %w", err)
	}
	return TimestampUTC(t), nil
}
