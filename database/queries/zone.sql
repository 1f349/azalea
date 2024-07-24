-- name: GetZones :many
SELECT *
FROM zones;

-- name: GetZone :one
SELECT *
FROM zones
WHERE name = ?;

-- name: GetOwnedZones :many
SELECT *
FROM zones
WHERE name IN(sqlc.slice(name));

-- name: AddZone :execlastid
INSERT INTO zones (name)
VALUES (?);
