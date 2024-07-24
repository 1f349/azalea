CREATE TABLE zones
(
    id   INTEGER PRIMARY KEY AUTO_INCREMENT NOT NULL,
    name TEXT UNIQUE                        NOT NULL
);

CREATE TABLE records
(
    id     INTEGER PRIMARY KEY AUTO_INCREMENT NOT NULL,
    zone   INTEGER                            NOT NULL,
    name   TEXT                               NOT NULL,
    type   TEXT                               NOT NULL,
    locked BOOLEAN                            NOT NULL,
    ttl    INTEGER,
    value  TEXT                               NOT NULL,

    FOREIGN KEY (zone) REFERENCES zones (id)
        ON DELETE RESTRICT
        ON UPDATE RESTRICT
);

CREATE INDEX record_name ON records (name);
CREATE INDEX record_type ON records (type);

CREATE TABLE services
(
    id        INTEGER PRIMARY KEY NOT NULL,
    name      TEXT UNIQUE         NOT NULL,
    available BOOLEAN             NOT NULL
);

CREATE TABLE service_records
(
    id        INTEGER PRIMARY KEY NOT NULL,
    service   INTEGER             NOT NULL,
    type      TEXT                NOT NULL,
    value     TEXT                NOT NULL,
    latitude  DECIMAL(8, 6)       NOT NULL,
    longitude DECIMAL(9, 6)       NOT NULL,

    FOREIGN KEY (service) REFERENCES services (id)
        ON DELETE RESTRICT
        ON UPDATE RESTRICT
);
