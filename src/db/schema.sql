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
    created_at  TIMESTAMP DEFAULT NOW(),
    relay_mode     VARCHAR(16) DEFAULT 'timed',
    relay_duration INTEGER DEFAULT 5,
    ble_name       TEXT
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
    created_at  TIMESTAMP DEFAULT NOW(),
    door_user_id INTEGER
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
    created_at  TIMESTAMP DEFAULT NOW(),
    restart_reason   TEXT,
    credentials      INTEGER,
    schedule_enabled BOOLEAN,
    schedule_start   TEXT,
    schedule_end     TEXT,
    mqtt_reconnects  INTEGER
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

/* People who open doors (distinct from app_users = mobile-app logins, and
   users = dashboard logins). */
CREATE TABLE IF NOT EXISTS door_users (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    active      BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_credentials (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES door_users(id) ON DELETE CASCADE,
    device_id   INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    type        VARCHAR(10) NOT NULL,
    identifier  VARCHAR(100) NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    cred_data   TEXT,
    CONSTRAINT user_credentials_type_check CHECK (type IN ('rfid','pin','qr'))
);

/* Upgrade path for databases created before these columns existed (idempotent). */
ALTER TABLE devices      ADD COLUMN IF NOT EXISTS relay_mode     VARCHAR(16) DEFAULT 'timed';
ALTER TABLE devices      ADD COLUMN IF NOT EXISTS relay_duration INTEGER DEFAULT 5;
ALTER TABLE devices      ADD COLUMN IF NOT EXISTS ble_name       TEXT;
ALTER TABLE access_logs  ADD COLUMN IF NOT EXISTS door_user_id   INTEGER;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS restart_reason   TEXT;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS credentials      INTEGER;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS schedule_enabled BOOLEAN;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS schedule_start   TEXT;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS schedule_end     TEXT;
ALTER TABLE heartbeats   ADD COLUMN IF NOT EXISTS mqtt_reconnects  INTEGER;

/* Presence: when the device was last heard from, and every period it was offline. */
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP;
UPDATE devices SET last_seen = (SELECT MAX(h.created_at) FROM heartbeats h WHERE h.device_id = devices.id)
 WHERE last_seen IS NULL;

CREATE TABLE IF NOT EXISTS device_outages (
    id         SERIAL PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    started_at TIMESTAMP NOT NULL,
    ended_at   TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_device_outages_dev ON device_outages (device_id, started_at DESC);
/* at most one open outage per device */
CREATE UNIQUE INDEX IF NOT EXISTS uq_device_outage_open ON device_outages (device_id) WHERE ended_at IS NULL;
