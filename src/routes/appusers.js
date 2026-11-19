const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const bcrypt  = require('bcrypt');
const { requirePerm, getAccessibleDevice } = require('../auth');
const { audit } = require('../audit');
require('dotenv').config();

/* Mobile-app users (people who open doors from the phone app).
   Each belongs to ONE customer (app_users.org_id) and may only be granted
   doors of that same customer. Managed with 'appusers.manage'. */
router.use(requirePerm('appusers.manage'));

const sameOrg = (a, b) => (a ?? null) === (b ?? null);

/* Returns the app user if the caller may touch it, else null (-> 404). */
async function getAppUser(req, id) {
    const uid = parseInt(id, 10);
    if (!Number.isInteger(uid)) return null;
    const r = await pool.query('SELECT * FROM app_users WHERE id = $1', [uid]);
    const u = r.rows[0];
    if (!u) return null;
    if (req.user.role === 'super_admin') return u;
    return u.org_id !== null && u.org_id === req.user.orgId ? u : null;
}

/* GET all app users (of the caller's customer) */
router.get('/', async (req, res) => {
    try {
        const isSuper = req.user.role === 'super_admin';
        const result = await pool.query(
            `SELECT u.id, u.username, u.full_name, u.is_active, u.created_at, u.org_id,
                    COUNT(uda.device_id) as door_count
             FROM app_users u
             LEFT JOIN user_door_access uda ON uda.user_id = u.id
             ${isSuper ? '' : 'WHERE u.org_id = $1'}
             GROUP BY u.id ORDER BY u.created_at DESC`,
            isSuper ? [] : [req.user.orgId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET user doors */
router.get('/:id/doors', async (req, res) => {
    try {
        const u = await getAppUser(req, req.params.id);
        if (!u) return res.status(404).json({ error: 'User not found' });

        const result = await pool.query(
            `SELECT d.id, d.mqtt_id, d.name, d.location
             FROM user_door_access uda
             JOIN devices d ON d.id = uda.device_id
             WHERE uda.user_id = $1`,
            [u.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST create app user */
router.post('/', async (req, res) => {
    const { username, password, full_name } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'username and password required' });
    if (password.length < 6)
        return res.status(400).json({ error: 'Password must be at least 6 characters' });

    try {
        /* A customer's staff always creates inside their own customer.
           super_admin may pass org_id; omitted = unassigned. */
        let orgId = req.user.orgId;
        if (req.user.role === 'super_admin') {
            orgId = null;
            if (req.body.org_id !== undefined && req.body.org_id !== null && req.body.org_id !== '') {
                orgId = parseInt(req.body.org_id, 10);
                const o = Number.isInteger(orgId)
                    ? await pool.query('SELECT id FROM organizations WHERE id = $1', [orgId])
                    : { rows: [] };
                if (o.rows.length === 0)
                    return res.status(400).json({ error: 'Customer (org_id) not found' });
            }
        }

        const hash   = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO app_users (username, password, full_name, org_id) VALUES ($1, $2, $3, $4) RETURNING id, username, full_name, is_active, created_at, org_id',
            [username, hash, full_name || '', orgId]
        );
        await audit(req, 'appUser.create', { targetType: 'app_user', targetId: result.rows[0].id, orgId, details: { username } });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505')
            return res.status(400).json({ error: 'Username already exists' });
        res.status(500).json({ error: err.message });
    }
});

/* PATCH toggle user active */
router.patch('/:id/toggle', async (req, res) => {
    try {
        const u = await getAppUser(req, req.params.id);
        if (!u) return res.status(404).json({ error: 'User not found' });

        const result = await pool.query(
            'UPDATE app_users SET is_active = NOT is_active WHERE id = $1 RETURNING *',
            [u.id]
        );
        await audit(req, 'appUser.toggle', { targetType: 'app_user', targetId: u.id, orgId: u.org_id, details: { is_active: result.rows[0].is_active } });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST grant door access */
router.post('/:id/doors', async (req, res) => {
    const { device_id } = req.body;
    if (!device_id)
        return res.status(400).json({ error: 'device_id required' });
    try {
        const u = await getAppUser(req, req.params.id);
        if (!u) return res.status(404).json({ error: 'User not found' });

        const device = await getAccessibleDevice(req.user, device_id);
        if (!device) return res.status(404).json({ error: 'Device not found' });

        if (!sameOrg(device.org_id, u.org_id))
            return res.status(400).json({ error: 'This user and this device belong to different customers' });

        await pool.query(
            'INSERT INTO user_door_access (user_id, device_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [u.id, device.id]
        );
        await audit(req, 'appUser.grantDoor', { targetType: 'app_user', targetId: u.id, orgId: u.org_id, details: { device_id: device.id } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE revoke door access */
router.delete('/:id/doors/:deviceId', async (req, res) => {
    try {
        const u = await getAppUser(req, req.params.id);
        if (!u) return res.status(404).json({ error: 'User not found' });

        await pool.query(
            'DELETE FROM user_door_access WHERE user_id = $1 AND device_id = $2',
            [u.id, req.params.deviceId]
        );
        await audit(req, 'appUser.revokeDoor', { targetType: 'app_user', targetId: u.id, orgId: u.org_id, details: { device_id: req.params.deviceId } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE app user */
router.delete('/:id', async (req, res) => {
    try {
        const u = await getAppUser(req, req.params.id);
        if (!u) return res.status(404).json({ error: 'User not found' });

        await pool.query('DELETE FROM app_users WHERE id = $1', [u.id]);
        await audit(req, 'appUser.delete', { targetType: 'app_user', targetId: u.id, orgId: u.org_id, details: { username: u.username } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
