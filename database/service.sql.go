// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: service.sql

package database

import (
	"context"
)

const getAllServiceRecords = `-- name: GetAllServiceRecords :many
SELECT id, service, type, value, lat, long
FROM service_records
`

func (q *Queries) GetAllServiceRecords(ctx context.Context) ([]ServiceRecord, error) {
	rows, err := q.db.QueryContext(ctx, getAllServiceRecords)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []ServiceRecord
	for rows.Next() {
		var i ServiceRecord
		if err := rows.Scan(
			&i.ID,
			&i.Service,
			&i.Type,
			&i.Value,
			&i.Lat,
			&i.Long,
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

const getAllServices = `-- name: GetAllServices :many
SELECT id, name, available
FROM services
`

func (q *Queries) GetAllServices(ctx context.Context) ([]Service, error) {
	rows, err := q.db.QueryContext(ctx, getAllServices)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Service
	for rows.Next() {
		var i Service
		if err := rows.Scan(&i.ID, &i.Name, &i.Available); err != nil {
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

const getBestLocationResolvedRecord = `-- name: GetBestLocationResolvedRecord :one
WITH distances as (SELECT service_records.id, service_records.service, service_records.type, service_records.value, service_records.lat, service_records.long,
                          cast(? - service_records.lat as float)  as lat_diff,
                          cast(? - service_records.long as float) as long_diff
                   FROM service_records
                            INNER JOIN services s ON s.id = service_records.service
                   WHERE s.name = ?
                     AND s.available = 1),
     distances2 as (SELECT distances.id, distances.service, distances.type, distances.value, distances.lat, distances.long, distances.lat_diff, distances.long_diff,
                           cast((lat_diff * lat_diff + long_diff * long_diff) as float)                 AS d1,
                           cast((lat_diff * lat_diff + (long_diff + 360) * (long_diff + 360)) as float) AS d2,
                           cast((lat_diff * lat_diff + (long_diff - 360) * (long_diff - 360)) as float) AS d3
                    FROM distances)
SELECT distances2.id, distances2.service, distances2.type, distances2.value, distances2.lat, distances2.long, distances2.lat_diff, distances2.long_diff, distances2.d1, distances2.d2, distances2.d3, cast(min(d1, d2, d3) as float) as distance
FROM distances2
ORDER BY distance
LIMIT 1
`

type GetBestLocationResolvedRecordParams struct {
	Lat  float64 `json:"lat"`
	Long float64 `json:"long"`
	Name string  `json:"name"`
}

type GetBestLocationResolvedRecordRow struct {
	ID       int64   `json:"id"`
	Service  int64   `json:"service"`
	Type     string  `json:"type"`
	Value    string  `json:"value"`
	Lat      float64 `json:"lat"`
	Long     float64 `json:"long"`
	LatDiff  float64 `json:"lat_diff"`
	LongDiff float64 `json:"long_diff"`
	D1       float64 `json:"d1"`
	D2       float64 `json:"d2"`
	D3       float64 `json:"d3"`
	Distance float64 `json:"distance"`
}

func (q *Queries) GetBestLocationResolvedRecord(ctx context.Context, arg GetBestLocationResolvedRecordParams) (GetBestLocationResolvedRecordRow, error) {
	row := q.db.QueryRowContext(ctx, getBestLocationResolvedRecord, arg.Lat, arg.Long, arg.Name)
	var i GetBestLocationResolvedRecordRow
	err := row.Scan(
		&i.ID,
		&i.Service,
		&i.Type,
		&i.Value,
		&i.Lat,
		&i.Long,
		&i.LatDiff,
		&i.LongDiff,
		&i.D1,
		&i.D2,
		&i.D3,
		&i.Distance,
	)
	return i, err
}
