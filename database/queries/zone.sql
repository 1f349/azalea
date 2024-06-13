-- name: GetZones :many
SELECT *
FROM zones;

-- name: AddZone :exec
INSERT INTO zones (name)
VALUES (?);

-- name: GetAllRecords :many
SELECT *
FROM records;

-- name: GetZoneRecords :many
SELECT *
FROM records
WHERE zone = ?;
