-- ============================================================
-- RBAC / multi-tenant schema
-- Idempotent: safe to run on every startup (after schema.sql).
-- Kept in its own file so it can be reused as a template in
-- other products (orgs + users + roles + audit are generic).
-- ============================================================

/* ── Customers (tenants) ── */
CREATE TABLE IF NOT EXISTS organizations (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(128) UNIQUE NOT NULL,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT NOW()
);

/* ── Dashboard users: role + tenant ── */
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name  VARCHAR(128);
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active  BOOLEAN DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS org_id     INTEGER REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS role       VARCHAR(16);
/* TRUE = operator/viewer sees ONLY the doors listed in dashboard_user_device_access
   (even if the list is empty). FALSE = all doors of the customer.
   An explicit flag, so deleting the last listed door can never widen access. */
ALTER TABLE users ADD COLUMN IF NOT EXISTS device_restricted BOOLEAN NOT NULL DEFAULT FALSE;

/* Every user that existed before RBAC was a full admin -> super_admin.
   Runs only while role is NULL, so it is a one-time promotion. */
UPDATE users SET role = 'super_admin' WHERE role IS NULL;

/* From now on a missing role means the least-privileged one. */
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'viewer';
ALTER TABLE users ALTER COLUMN role SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_check') THEN
        ALTER TABLE users ADD CONSTRAINT users_role_check
            CHECK (role IN ('super_admin', 'org_admin', 'operator', 'viewer'));
    END IF;

    /* super_admin belongs to the platform (no org); everyone else must belong to one org. */
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_role_org_check') THEN
        ALTER TABLE users ADD CONSTRAINT users_role_org_check
            CHECK (
                (role = 'super_admin' AND org_id IS NULL) OR
                (role <> 'super_admin' AND org_id IS NOT NULL)
            );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id);

/* ── Devices belong to a customer. NULL = unassigned (platform owner only). ── */
ALTER TABLE devices ADD COLUMN IF NOT EXISTS org_id INTEGER REFERENCES organizations(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_devices_org_id ON devices(org_id);

/* ── Per-door restriction for operator/viewer inside an org (used when
   users.device_restricted = TRUE) ── */
CREATE TABLE IF NOT EXISTS dashboard_user_device_access (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at  TIMESTAMP DEFAULT NOW(),
    UNIQUE (user_id, device_id)
);

/* ── Audit trail ── */
CREATE TABLE IF NOT EXISTS audit_log (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username     VARCHAR(64),           -- snapshot, survives user deletion
    org_id       INTEGER,               -- tenant the action was performed in (NULL = platform)
    action       VARCHAR(64) NOT NULL,  -- e.g. 'device.command', 'credential.delete'
    target_type  VARCHAR(32),
    target_id    VARCHAR(64),
    details      JSONB,
    ip           VARCHAR(64),
    created_at   TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_org_created ON audit_log(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user        ON audit_log(user_id);

/* ── Door users (people who use the door) and mobile app users belong to a
   customer too. These tables were created by hand on the live database and
   are not in schema.sql, so only touch them when they exist. ── */
DO $$
BEGIN
    IF to_regclass('public.door_users') IS NOT NULL THEN
        ALTER TABLE door_users ADD COLUMN IF NOT EXISTS org_id INTEGER REFERENCES organizations(id) ON DELETE RESTRICT;
        CREATE INDEX IF NOT EXISTS idx_door_users_org_id ON door_users(org_id);
    END IF;

    IF to_regclass('public.app_users') IS NOT NULL THEN
        ALTER TABLE app_users ADD COLUMN IF NOT EXISTS org_id INTEGER REFERENCES organizations(id) ON DELETE RESTRICT;
        CREATE INDEX IF NOT EXISTS idx_app_users_org_id ON app_users(org_id);
    END IF;
END $$;
