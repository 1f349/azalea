-- name: GetBestLocationResolvedRecord :one
WITH distances as (SELECT service_records.*,
                          cast(? - service_records.lat as float)  as lat_diff,
                          cast(? - service_records.long as float) as long_diff
                   FROM service_records
                            INNER JOIN services s ON s.id = service_records.service
                   WHERE s.name = ?
                     AND s.available = 1),
     distances2 as (SELECT distances.*,
                           cast((lat_diff * lat_diff + long_diff * long_diff) as float)                 AS d1,
                           cast((lat_diff * lat_diff + (long_diff + 360) * (long_diff + 360)) as float) AS d2,
                           cast((lat_diff * lat_diff + (long_diff - 360) * (long_diff - 360)) as float) AS d3
                    FROM distances)
SELECT distances2.*, cast(min(d1, d2, d3) as float) as distance
FROM distances2
ORDER BY distance
LIMIT 1;

-- name: GetAllServices :many
SELECT *
FROM services;

-- name: GetAllServiceRecords :many
SELECT *
FROM service_records;
