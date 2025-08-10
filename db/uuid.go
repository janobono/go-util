package db

import (
	"log"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/samborkent/uuidv7"
)

func NewUUID() pgtype.UUID {
	u := uuidv7.New()
	result, err := ParseUUID(u.String())
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func ParseUUID(uuid string) (pgtype.UUID, error) {
	var pgUUID pgtype.UUID
	err := pgUUID.Scan(uuid)
	if err != nil {
		return pgUUID, err
	}
	return pgUUID, nil
}
