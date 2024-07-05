-- name: GetZoneRecords :many
SELECT records.*
FROM records
         INNER JOIN zones z on z.id = records.zone
WHERE z.name = ?;

-- name: LookupRecordsForType :many
SELECT records.*, z.name as zone_name
FROM records
         INNER JOIN zones z on z.id = records.zone
WHERE (type = ? or type = 'LOC_RES')
  and records.name = ?
  and z.name = ?;

-- name: AddZoneRecord :execlastid
INSERT INTO records (zone, name, type, locked, value)
VALUES (?, ?, ?, ?, ?);

-- name: GetZoneRecordById :one
SELECT records.*
FROM records
WHERE zone = ?
  AND id = ?;

-- name: PutZoneRecordById :exec
UPDATE records
SET value = ?
WHERE zone = ?
  AND id = ?;

-- name: DeleteZoneRecordById :exec
DELETE
FROM records
WHERE zone = ?
  AND id = ?;
