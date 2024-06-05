CREATE TABLE soa_records
(
    id      INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name    TEXT UNIQUE                              NOT NULL,
    ns      TEXT                                     NOT NULL,
    mbox    TEXT                                     NOT NULL,
    serial  INTEGER                                  NOT NULL,
    refresh INTEGER                                  NOT NULL,
    retry   INTEGER                                  NOT NULL,
    expire  INTEGER                                  NOT NULL,
    ttl     INTEGER                                  NOT NULL
);

CREATE TABLE a_records
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name  TEXT                                     NOT NULL,
    value TEXT                                     NOT NULL,
    ttl   INTEGER                                  NOT NULL
);

CREATE TABLE aaaa_records
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name  TEXT                                     NOT NULL,
    value TEXT                                     NOT NULL,
    ttl   INTEGER                                  NOT NULL
);

CREATE TABLE cname_records
(
    id    INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name  TEXT                                     NOT NULL,
    value TEXT                                     NOT NULL,
    ttl   INTEGER                                  NOT NULL
);

CREATE TABLE mx_records
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name     TEXT                                     NOT NULL,
    priority INTEGER                                  NOT NULL,
    value    TEXT                                     NOT NULL,
    ttl      INTEGER                                  NOT NULL
);

CREATE TABLE txt_records
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name     TEXT                                     NOT NULL,
    priority INTEGER                                  NOT NULL,
    value    TEXT                                     NOT NULL,
    ttl      INTEGER                                  NOT NULL
);

CREATE TABLE srv_records
(
    id       INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
    name     TEXT                                     NOT NULL,
    target   TEXT                                     NOT NULL,
    priority INTEGER                                  NOT NULL,
    weight   INTEGER                                  NOT NULL,
    port     INTEGER                                  NOT NULL,
    ttl      INTEGER                                  NOT NULL
);
