const express = require('express');
const bcrypt  = require('bcrypt');
const router  = express.Router();
const pool    = require('../db/pool');
const { requirePerm, getAccessibleDevice } = require('../auth');
const { audit } = require('../audit');

/* Dashboard logins (the people who sign in to this website).
   - super_admin: manages everybody, any role, any customer.
   - org_admin:   manages only users of OWN customer, and can never create or
                  touch a super_admin.
   Both need 'users.manage'. */
router.use(requirePerm('users.manage'));

const ROLES           = ['super_admin', 'org_admin', 'operator', 'viewer'];
const CUSTOMER_ROLES  = ['org_admin', 'operator', 'viewer'];
const USERNAME_RE     = /^[A-Za-z0-9._@-]{3,64}$/;
const MIN_PASSWORD    = 8;

const isSuper = (req) => req.user.role === 'super_admin';
const hub     = (req) => req.app.locals.hub;

/* The target user, if the caller is allowed to manage it (else null -> 404). */
async function getManagedUser(req, id) {
    const uid = parseInt(id, 10);
    if (!Number.isInteger(uid)) return null;
    const r = await pool.query(
        'SELECT id, username, full_name, role, org_id, is_active, created_at FROM users WHERE id = $1',
        [uid]
    );
    const u = r.rows[0];
    if (!u) return null;
    if (isSuper(req)) return u;
    if (u.role === 'super_admin') return null;
    return u.org_id === req.user.orgId ? u : null;
}

/* Never remove the last active super_admin (would lock everyone out). */
async function otherActiveSuperExists(excludeId) {
    const r = await pool.query(
        "SELECT 1 FROM users WHERE role = 'super_admin' AND is_active = TRUE AND id <> $1 LIMIT 1",
        [excludeId]
    );
    return r.rows.length > 0;
}

/* GET users in scope */
router.get('/', async (req, res) => {
    try {
        const result = isSuper(req)
            ? await pool.query(
                `SELECT u.id, u.username, u.full_name, u.role, u.org_id, u.is_active, u.device_restricted, u.created_at, o.name AS org_name
                   FROM users u LEFT JOIN organizations o ON o.id = u.org_id
                  ORDER BY u.org_id NULLS FIRST, u.username`)
            : await pool.query(
                `SELECT u.id, u.username, u.full_name, u.role, u.org_id, u.is_active, u.device_restricted, u.created_at, o.name AS org_name
                   FROM users u LEFT JOIN organizations o ON o.id = u.org_id
                  WHERE u.org_id = $1 AND u.role <> 'super_admin'
                  ORDER BY u.username`, [req.user.orgId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST create user */
router.post('/', async (req, res) => {
    const { username, password, full_name } = req.body;
    const role = req.body.role || 'viewer';

    if (!username || !USERNAME_RE.test(username))
        return res.status(400).json({ error: 'username must be 3–64 chars: letters, digits . _ @ -' });
    if (!password || password.length < MIN_PASSWORD)
        return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD} characters` });
    if (!ROLES.includes(role))
        return res.status(400).json({ error: 'invalid role' });

    let orgId;
    if (isSuper(req)) {
        if (role === 'super_admin') {
            orgId = null;
        } else {
            orgId = parseInt(req.body.org_id, 10);
            const o = Number.isInteger(orgId)
                ? await pool.query('SELECT id FROM organizations WHERE id = $1', [orgId])
                : { rows: [] };
            if (o.rows.length === 0)
                return res.status(400).json({ error: 'org_id (customer) is required for this role' });
        }
    } else {
        if (!CUSTOMER_ROLES.includes(role))
            return res.status(403).json({ error: 'You cannot create this role' });
        orgId = req.user.orgId;                 /* forced: a customer admin only creates inside their customer */
    }

    try {
        const hash   = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (username, password, full_name, role, org_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, username, full_name, role, org_id, is_active, created_at`,
            [username, hash, full_name || '', role, orgId]
        );
        await audit(req, 'user.create', { targetType: 'user', targetId: result.rows[0].id, orgId, details: { username, role } });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
        res.status(500).json({ error: err.message });
    }
});

/* PATCH update user: full_name, role, is_active, password reset */
router.patch('/:id', async (req, res) => {
    try {
        const target = await getManagedUser(req, req.params.id);
        if (!target) return res.status(404).json({ error: 'User not found' });

        const isSelf = target.id === req.user.id;
        const sets = [], params = [];
        const details = {};

        if (req.body.full_name !== undefined) {
            params.push(String(req.body.full_name)); sets.push(`full_name = $${params.length}`);
        }

        if (req.body.role !== undefined && req.body.role !== target.role) {
            const role = req.body.role;
            if (!ROLES.includes(role)) return res.status(400).json({ error: 'invalid role' });
            if (isSelf) return res.status(400).json({ error: 'You cannot change your own role' });
            if (!isSuper(req) && !CUSTOMER_ROLES.includes(role))
                return res.status(403).json({ error: 'You cannot assign this role' });
            if (role === 'super_admin' && target.org_id !== null)
                return res.status(400).json({ error: 'A platform admin cannot belong to a customer' });
            if (role !== 'super_admin' && target.org_id === null)
                return res.status(400).json({ error: 'Assign the user to a customer before giving this role' });
            if (target.role === 'super_admin' && !(await otherActiveSuperExists(target.id)))
                return res.status(400).json({ error: 'Cannot demote the last super admin' });
            params.push(role); sets.push(`role = $${params.length}`);
            details.role = role;
        }

        if (req.body.is_active !== undefined) {
            const active = !!req.body.is_active;
            if (!active && isSelf) return res.status(400).json({ error: 'You cannot disable yourself' });
            if (!active && target.role === 'super_admin' && !(await otherActiveSuperExists(target.id)))
                return res.status(400).json({ error: 'Cannot disable the last super admin' });
            params.push(active); sets.push(`is_active = $${params.length}`);
            details.is_active = active;
        }

        if (req.body.password !== undefined) {
            if (String(req.body.password).length < MIN_PASSWORD)
                return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD} characters` });
            params.push(await bcrypt.hash(String(req.body.password), 10)); sets.push(`password = $${params.length}`);
            details.password_reset = true;           /* the password itself is never logged */
        }

        if (sets.length === 0) return res.status(400).json({ error: 'nothing to update' });

        params.push(target.id);
        const result = await pool.query(
            `UPDATE users SET ${sets.join(', ')} WHERE id = $${params.length}
             RETURNING id, username, full_name, role, org_id, is_active, created_at`,
            params
        );

        /* Role / status / password changed: drop its live WebSocket connections now. */
        if (hub(req) && (details.role || details.is_active === false || details.password_reset))
            hub(req).disconnectUser(target.id);

        await audit(req, 'user.update', { targetType: 'user', targetId: target.id, orgId: target.org_id, details });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE user */
router.delete('/:id', async (req, res) => {
    try {
        const target = await getManagedUser(req, req.params.id);
        if (!target) return res.status(404).json({ error: 'User not found' });
        if (target.id === req.user.id) return res.status(400).json({ error: 'You cannot delete yourself' });
        if (target.role === 'super_admin' && !(await otherActiveSuperExists(target.id)))
            return res.status(400).json({ error: 'Cannot delete the last super admin' });

        await pool.query('DELETE FROM users WHERE id = $1', [target.id]);
        if (hub(req)) hub(req).disconnectUser(target.id);
        await audit(req, 'user.delete', { targetType: 'user', targetId: target.id, orgId: target.org_id, details: { username: target.username } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET the door restriction of an operator/viewer.
   restricted=false -> sees all doors of the customer. */
router.get('/:id/devices', async (req, res) => {
    try {
        const target = await getManagedUser(req, req.params.id);
        if (!target) return res.status(404).json({ error: 'User not found' });
        const u = await pool.query('SELECT device_restricted FROM users WHERE id = $1', [target.id]);
        const r = await pool.query(
            'SELECT device_id FROM dashboard_user_device_access WHERE user_id = $1 ORDER BY device_id',
            [target.id]
        );
        res.json({ restricted: u.rows[0].device_restricted, device_ids: r.rows.map(x => x.device_id) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* PUT replace the restriction.
   Body: { restricted: boolean, device_ids: [..] }
   restricted=false -> all doors of the customer (list cleared).
   restricted=true  -> only the listed doors (an empty list = no door). */
router.put('/:id/devices', async (req, res) => {
    try {
        const target = await getManagedUser(req, req.params.id);
        if (!target) return res.status(404).json({ error: 'User not found' });
        if (target.role === 'super_admin' || target.role === 'org_admin')
            return res.status(400).json({ error: 'Door restrictions apply to operators and viewers only' });

        const restricted = !!req.body.restricted;
        const ids = restricted && Array.isArray(req.body.device_ids)
            ? req.body.device_ids.map(n => parseInt(n, 10)) : [];
        if (ids.some(n => !Number.isInteger(n)))
            return res.status(400).json({ error: 'device_ids must be an array of numbers' });

        /* every door must belong to the user's customer AND be visible to the caller */
        for (const id of ids) {
            const d = await getAccessibleDevice(req.user, id);
            if (!d || d.org_id !== target.org_id)
                return res.status(400).json({ error: `Device ${id} is not available for this user` });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query('DELETE FROM dashboard_user_device_access WHERE user_id = $1', [target.id]);
            for (const id of [...new Set(ids)])
                await client.query('INSERT INTO dashboard_user_device_access (user_id, device_id) VALUES ($1, $2)', [target.id, id]);
            await client.query('UPDATE users SET device_restricted = $1 WHERE id = $2', [restricted, target.id]);
            await client.query('COMMIT');
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }

        if (hub(req)) hub(req).disconnectUser(target.id);      /* reconnects with the new restriction */
        await audit(req, 'user.setDevices', { targetType: 'user', targetId: target.id, orgId: target.org_id, details: { restricted, device_ids: ids } });
        res.json({ success: true, restricted, device_ids: ids });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
