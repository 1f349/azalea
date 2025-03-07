// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: zone.sql

package database

import (
	"context"
	"strings"
)

const addZone = `-- name: AddZone :execlastid
INSERT INTO zones (name)
VALUES (?)
`

func (q *Queries) AddZone(ctx context.Context, name string) (int64, error) {
	result, err := q.db.ExecContext(ctx, addZone, name)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

const getOwnedZones = `-- name: GetOwnedZones :many
SELECT id, name
FROM zones
WHERE name IN(/*SLICE:name*/?)
`

func (q *Queries) GetOwnedZones(ctx context.Context, name []string) ([]Zone, error) {
	query := getOwnedZones
	var queryParams []interface{}
	if len(name) > 0 {
		for _, v := range name {
			queryParams = append(queryParams, v)
		}
		query = strings.Replace(query, "/*SLICE:name*/?", strings.Repeat(",?", len(name))[1:], 1)
	} else {
		query = strings.Replace(query, "/*SLICE:name*/?", "NULL", 1)
	}
	rows, err := q.db.QueryContext(ctx, query, queryParams...)
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

const getZone = `-- name: GetZone :one
SELECT id, name
FROM zones
WHERE name = ?
`

func (q *Queries) GetZone(ctx context.Context, name string) (Zone, error) {
	row := q.db.QueryRowContext(ctx, getZone, name)
	var i Zone
	err := row.Scan(&i.ID, &i.Name)
	return i, err
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
