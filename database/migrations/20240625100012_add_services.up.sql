CREATE TABLE services
(
    id        INTEGER PRIMARY KEY UNIQUE NOT NULL,
    name      TEXT UNIQUE                NOT NULL,
    available BOOLEAN                    NOT NULL
);

CREATE TABLE service_records
(
    id      INTEGER PRIMARY KEY UNIQUE NOT NULL,
    service INTEGER                    NOT NULL,
    type    TEXT                       NOT NULL,
    value   TEXT                       NOT NULL,
    lat     DECIMAL(8, 6)              NOT NULL,
    long    DECIMAL(9, 6)              NOT NULL,

    FOREIGN KEY (service) REFERENCES services (id)
);
