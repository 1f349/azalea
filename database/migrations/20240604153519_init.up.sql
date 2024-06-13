CREATE TABLE zones
(
    id   INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name TEXT UNIQUE                              NOT NULL
);

CREATE TABLE records
(
    id     INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    zone   INTEGER                                  NOT NULL,
    name   TEXT                                     NOT NULL,
    type   TEXT                                     NOT NULL,
    locked BOOLEAN                                  NOT NULL,
    ttl    INTEGER,
    value  TEXT                                     NOT NULL,

    FOREIGN KEY (zone) REFERENCES zones (id)
);
