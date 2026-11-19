/* ============================================================
   Authentication + authorization core (RBAC, multi-tenant).

   Generic on purpose: nothing here knows about doors. Product
   specific permissions live in ROLE_PERMS below; everything else
   (session loading, tenant scoping, device ownership) can be
   reused as-is in another product.

   Security rules enforced here:
   - The user is re-read from the DB on EVERY request, so a
     disabled user / disabled customer / changed role takes effect
     immediately (no stale session privileges).
   - A device the caller may not access answers 404, not 403, so
     device ids of other customers cannot be probed.
   ============================================================ */
const pool = require('./db/pool');

const ALL = '*';

/* ── Permission matrix ───────────────────────────────────────
   Anything not listed for a role is denied. Platform-only
   actions (serials, device create/delete/activate, OTA, customer
   management) are deliberately absent from every role except
   super_admin, which holds '*'.                                */
const ROLE_PERMS = {
    super_admin: [ALL],

    org_admin: [
        'device.view', 'device.command', 'device.configure',
        'logs.view', 'logs.export',
        'credentials.view', 'credentials.manage',
        'temppin.manage',
        'doorusers.manage',
        'appusers.manage',
        'users.manage',          /* manage users of OWN organization only */
        'audit.view'
    ],

    operator: [
        'device.view', 'device.command',
        'logs.view',
        'credentials.view',
        'temppin.manage'
    ],

    viewer: [
        'device.view',
        'logs.view'
    ]
};

function hasPerm(role, perm) {
    const perms = ROLE_PERMS[role];
    if (!perms) return false;
    return perms.includes(ALL) || perms.includes(perm);
}

function permsForRole(role) {
    return ROLE_PERMS[role] ? [...ROLE_PERMS[role]] : [];
}

/* ── user id -> fresh user record (null if missing / disabled / customer disabled) ── */
async function loadUserById(id) {
    if (!id) return null;

    const r = await pool.query(
        `SELECT u.id, u.username, u.full_name, u.role, u.org_id, u.is_active, u.device_restricted,
                o.name AS org_name, o.is_active AS org_active
           FROM users u
           LEFT JOIN organizations o ON o.id = u.org_id
          WHERE u.id = $1`,
        [id]
    );
    const u = r.rows[0];
    if (!u || !u.is_active) return null;
    if (u.org_id !== null && !u.org_active) return null;

    return {
        id:       u.id,
        username: u.username,
        fullName: u.full_name,
        role:     u.role,
        orgId:    u.org_id,
        orgName:  u.org_name,
        deviceRestricted: u.device_restricted
    };
}

/* ── Session -> fresh user record ── */
async function loadSessionUser(req) {
    return loadUserById(req.session && req.session.userId);
}

/* Devices an operator/viewer is restricted to (Set of device ids, possibly
   EMPTY = no door at all), or null when the user is not restricted
   (= all devices of the customer). */
async function loadDeviceRestriction(user) {
    if (user.role === 'super_admin' || user.role === 'org_admin') return null;
    if (!user.deviceRestricted) return null;
    const r = await pool.query(
        'SELECT device_id FROM dashboard_user_device_access WHERE user_id = $1',
        [user.id]
    );
    return new Set(r.rows.map(x => x.device_id));
}

function wantsJson(req) {
    return req.path.startsWith('/api/') || req.originalUrl.startsWith('/api/');
}

/* ── Middleware: must be logged in. Sets req.user ── */
async function requireAuth(req, res, next) {
    try {
        const user = await loadSessionUser(req);
        if (user) {
            req.user = user;
            return next();
        }
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
    if (wantsJson(req)) return res.status(401).json({ error: 'Unauthorized' });
    res.redirect('/login.html');
}

/* ── Middleware factory: must hold a permission ── */
function requirePerm(perm) {
    return (req, res, next) => {
        if (!req.user || !hasPerm(req.user.role, perm)) {
            if (wantsJson(req)) return res.status(403).json({ error: 'Forbidden' });
            return res.status(403).send('Forbidden');
        }
        next();
    };
}

/* ── Device ownership ──────────────────────────────────────── */

/* Returns the device row if `user` may access it, otherwise null.
   - super_admin: any device
   - org_admin:   devices of own org
   - operator/viewer: devices of own org; if users.device_restricted is
     TRUE, ONLY those listed in dashboard_user_device_access.            */
async function getAccessibleDevice(user, deviceId) {
    const id = parseInt(deviceId, 10);
    if (!Number.isInteger(id)) return null;

    const r = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
    const device = r.rows[0];
    if (!device) return null;

    if (user.role === 'super_admin') return device;
    if (device.org_id === null || device.org_id !== user.orgId) return null;
    if (user.role === 'org_admin') return device;

    if (!user.deviceRestricted) return device;
    const restr = await pool.query(
        'SELECT 1 FROM dashboard_user_device_access WHERE user_id = $1 AND device_id = $2',
        [user.id, device.id]
    );
    return restr.rows.length > 0 ? device : null;
}

/* Middleware factory for routes shaped /:id/...  — checks the
   permission AND that the device belongs to the caller. Sets
   req.device.                                                   */
function requireDevice(perm, param = 'id') {
    return async (req, res, next) => {
        try {
            if (!req.user || !hasPerm(req.user.role, perm))
                return res.status(403).json({ error: 'Forbidden' });

            const device = await getAccessibleDevice(req.user, req.params[param]);
            if (!device)
                return res.status(404).json({ error: 'Device not found' });

            req.device = device;
            next();
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    };
}

/* SQL fragment limiting a query to the devices `user` may see.
   Usage:
     const s = deviceScope(req.user, 'd', 1);
     pool.query(`SELECT d.* FROM devices d WHERE ${s.clause}`, s.params);
   `startIdx` is the first free $n placeholder.                  */
function deviceScope(user, alias = 'd', startIdx = 1) {
    if (user.role === 'super_admin') {
        return { clause: 'TRUE', params: [] };
    }
    const orgP = `$${startIdx}`;
    if (user.role === 'org_admin') {
        return { clause: `${alias}.org_id = ${orgP}`, params: [user.orgId] };
    }
    if (!user.deviceRestricted) {
        return { clause: `${alias}.org_id = ${orgP}`, params: [user.orgId] };
    }
    const userP = `$${startIdx + 1}`;
    return {
        clause:
            `${alias}.org_id = ${orgP} AND ` +
            `${alias}.id IN (SELECT device_id FROM dashboard_user_device_access WHERE user_id = ${userP})`,
        params: [user.orgId, user.id]
    };
}

module.exports = {
    ROLE_PERMS,
    hasPerm,
    permsForRole,
    loadSessionUser,
    loadUserById,
    loadDeviceRestriction,
    requireAuth,
    requirePerm,
    requireDevice,
    getAccessibleDevice,
    deviceScope
};
