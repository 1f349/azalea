-- name: GetAllSoaRecords :many
SELECT *
FROM soa_records;

-- name: GetAllARecords :many
SELECT *
FROM a_records;

-- name: GetAllAAAARecords :many
SELECT *
FROM aaaa_records;

-- name: GetAllCnameRecords :many
SELECT *
FROM cname_records;

-- name: GetAllMxRecords :many
SELECT *
FROM mx_records;

-- name: GetAllTxtRecords :many
SELECT *
FROM txt_records;

-- name: GetAllSrvRecords :many
SELECT *
FROM srv_records;
