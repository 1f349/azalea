-- name: GetBestLocationResolvedRecord :one
SELECT service_records.*, SQRT(POWER(? - service_records.lat, 2) + POWER(? - service_records.long, 2)) AS distance
FROM service_records
         INNER JOIN services s ON s.id = service_records.service
WHERE s.name = ?
  AND s.available
ORDER BY distance
LIMIT 1;

-- name: GetAllServices :many
SELECT *
FROM services;

-- name: GetAllServiceRecords :many
SELECT *
FROM service_records;
