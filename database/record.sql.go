// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: record.sql

package database

import (
	"context"
	"database/sql"
)

const addZoneRecord = `-- name: AddZoneRecord :execlastid
INSERT INTO records (zone, name, type, locked, value)
VALUES (?, ?, ?, ?, ?)
`

type AddZoneRecordParams struct {
	Zone   int64  `json:"zone"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Locked bool   `json:"locked"`
	Value  string `json:"value"`
}

func (q *Queries) AddZoneRecord(ctx context.Context, arg AddZoneRecordParams) (int64, error) {
	result, err := q.db.ExecContext(ctx, addZoneRecord,
		arg.Zone,
		arg.Name,
		arg.Type,
		arg.Locked,
		arg.Value,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

const deleteZoneRecordById = `-- name: DeleteZoneRecordById :exec
DELETE
FROM records
WHERE zone = ?
  AND id = ?
`

type DeleteZoneRecordByIdParams struct {
	Zone int64 `json:"zone"`
	ID   int64 `json:"id"`
}

func (q *Queries) DeleteZoneRecordById(ctx context.Context, arg DeleteZoneRecordByIdParams) error {
	_, err := q.db.ExecContext(ctx, deleteZoneRecordById, arg.Zone, arg.ID)
	return err
}

const getZoneRecordById = `-- name: GetZoneRecordById :one
SELECT records.id, records.zone, records.name, records.type, records.locked, records.ttl, records.value
FROM records
WHERE zone = ?
  AND id = ?
`

type GetZoneRecordByIdParams struct {
	Zone int64 `json:"zone"`
	ID   int64 `json:"id"`
}

func (q *Queries) GetZoneRecordById(ctx context.Context, arg GetZoneRecordByIdParams) (Record, error) {
	row := q.db.QueryRowContext(ctx, getZoneRecordById, arg.Zone, arg.ID)
	var i Record
	err := row.Scan(
		&i.ID,
		&i.Zone,
		&i.Name,
		&i.Type,
		&i.Locked,
		&i.Ttl,
		&i.Value,
	)
	return i, err
}

const getZoneRecords = `-- name: GetZoneRecords :many
SELECT records.id, records.zone, records.name, records.type, records.locked, records.ttl, records.value
FROM records
         INNER JOIN zones z on z.id = records.zone
WHERE z.name = ?
`

func (q *Queries) GetZoneRecords(ctx context.Context, name string) ([]Record, error) {
	rows, err := q.db.QueryContext(ctx, getZoneRecords, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Record
	for rows.Next() {
		var i Record
		if err := rows.Scan(
			&i.ID,
			&i.Zone,
			&i.Name,
			&i.Type,
			&i.Locked,
			&i.Ttl,
			&i.Value,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const lookupRecordsForType = `-- name: LookupRecordsForType :many
SELECT records.id, records.zone, records.name, records.type, records.locked, records.ttl, records.value, z.name as zone_name
FROM records
         INNER JOIN zones z on z.id = records.zone
WHERE (type = ? or type = 'LOC_RES')
  and records.name = ?
  and z.name = ?
`

type LookupRecordsForTypeParams struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Name_2 string `json:"name_2"`
}

type LookupRecordsForTypeRow struct {
	ID       int64         `json:"id"`
	Zone     int64         `json:"zone"`
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Locked   bool          `json:"locked"`
	Ttl      sql.NullInt64 `json:"ttl"`
	Value    string        `json:"value"`
	ZoneName string        `json:"zone_name"`
}

func (q *Queries) LookupRecordsForType(ctx context.Context, arg LookupRecordsForTypeParams) ([]LookupRecordsForTypeRow, error) {
	rows, err := q.db.QueryContext(ctx, lookupRecordsForType, arg.Type, arg.Name, arg.Name_2)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LookupRecordsForTypeRow
	for rows.Next() {
		var i LookupRecordsForTypeRow
		if err := rows.Scan(
			&i.ID,
			&i.Zone,
			&i.Name,
			&i.Type,
			&i.Locked,
			&i.Ttl,
			&i.Value,
			&i.ZoneName,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const putZoneRecordById = `-- name: PutZoneRecordById :exec
UPDATE records
SET value = ?
WHERE zone = ?
  AND id = ?
`

type PutZoneRecordByIdParams struct {
	Value string `json:"value"`
	Zone  int64  `json:"zone"`
	ID    int64  `json:"id"`
}

func (q *Queries) PutZoneRecordById(ctx context.Context, arg PutZoneRecordByIdParams) error {
	_, err := q.db.ExecContext(ctx, putZoneRecordById, arg.Value, arg.Zone, arg.ID)
	return err
}