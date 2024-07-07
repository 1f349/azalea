// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: zone.sql

package database

import (
	"context"
)

const addZone = `-- name: AddZone :exec
INSERT INTO zones (name)
VALUES (?)
`

func (q *Queries) AddZone(ctx context.Context, name string) error {
	_, err := q.db.ExecContext(ctx, addZone, name)
	return err
}

const getAllRecords = `-- name: GetAllRecords :many
SELECT id, zone, name, type, locked, ttl, value
FROM records
`

func (q *Queries) GetAllRecords(ctx context.Context) ([]Record, error) {
	rows, err := q.db.QueryContext(ctx, getAllRecords)
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

const getZoneRecords = `-- name: GetZoneRecords :many
SELECT id, zone, name, type, locked, ttl, value
FROM records
WHERE zone = ?
`

func (q *Queries) GetZoneRecords(ctx context.Context, zone int64) ([]Record, error) {
	rows, err := q.db.QueryContext(ctx, getZoneRecords, zone)
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

const getZones = `-- name: GetZones :many
SELECT id, name
FROM zones
`

func (q *Queries) GetZones(ctx context.Context) ([]Zone, error) {
	rows, err := q.db.QueryContext(ctx, getZones)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Zone
	for rows.Next() {
		var i Zone
		if err := rows.Scan(&i.ID, &i.Name); err != nil {
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