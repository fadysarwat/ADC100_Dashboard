-- ADC-100 Dashboard Database Schema

CREATE TABLE IF NOT EXISTS serials (
    id          SERIAL PRIMARY KEY,
    serial      VARCHAR(64) UNIQUE NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW(),
    assigned_at TIMESTAMP,
    device_id   INTEGER
);

CREATE TABLE IF NOT EXISTS devices (
    id          SERIAL PRIMARY KEY,
    serial      VARCHAR(64) UNIQUE NOT NULL,
    mqtt_id     VARCHAR(64) UNIQUE,
    name        VARCHAR(128),
    location    VARCHAR(128),
    notes       TEXT DEFAULT '',
    status      VARCHAR(16) DEFAULT 'offline',
    activated   BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS credentials (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    label       VARCHAR(64),
    cred_type   VARCHAR(8),
    cred_data   VARCHAR(128),
    is_duress   BOOLEAN DEFAULT FALSE,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_logs (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    method      VARCHAR(16),
    result      VARCHAR(16),
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS heartbeats (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    fw          VARCHAR(16),
    uptime      INTEGER,
    rssi        INTEGER,
    ip          VARCHAR(16),
    free_heap   INTEGER,
    door        VARCHAR(8),
    relay       VARCHAR(8),
    tamper      VARCHAR(8),
    fire        VARCHAR(8),
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS schedules (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE UNIQUE,
    enabled     BOOLEAN DEFAULT FALSE,
    start_time  VARCHAR(5) DEFAULT '08:00',
    end_time    VARCHAR(5) DEFAULT '18:00',
    updated_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS temp_pins (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    pin         VARCHAR(4) NOT NULL,
    label       VARCHAR(64),
    iat         TIMESTAMP NOT NULL,
    exp         TIMESTAMP NOT NULL,
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) UNIQUE NOT NULL,
    password    VARCHAR(128) NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64) UNIQUE NOT NULL,
    password    VARCHAR(128) NOT NULL,
    full_name   VARCHAR(128),
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_door_access (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES app_users(id) ON DELETE CASCADE,
    device_id  INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, device_id)
);