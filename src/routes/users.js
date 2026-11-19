const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { publish } = require('../mqtt');
const crypto  = require('crypto');
const { requirePerm, getAccessibleDevice } = require('../auth');
const { audit } = require('../audit');
const { buildCommand } = require('../devicesig');
require('dotenv').config();

/* "Door users" = the people who use the doors (not dashboard logins).
   Each belongs to ONE customer (door_users.org_id).
   - super_admin: all of them (org_id NULL = not yet assigned to a customer)
   - everyone else: only their own customer's, and only with 'doorusers.manage' */
router.use(requirePerm('doorusers.manage'));

const sameOrg = (a, b) => (a ?? null) === (b ?? null);

/* Returns the door user if the caller may touch it, else null (-> 404). */
async function getDoorUser(req, id) {
    const uid = parseInt(id, 10);
    if (!Number.isInteger(uid)) return null;
    const r = await pool.query('SELECT * FROM door_users WHERE id = $1', [uid]);
    const du = r.rows[0];
    if (!du) return null;
    if (req.user.role === 'super_admin') return du;
    return du.org_id !== null && du.org_id === req.user.orgId ? du : null;
}

/* GET all door users (of the caller's customer) */
router.get('/', async (req, res) => {
    try {
        const result = req.user.role === 'super_admin'
            ? await pool.query('SELECT * FROM door_users ORDER BY name ASC')
            : await pool.query('SELECT * FROM door_users WHERE org_id = $1 ORDER BY name ASC', [req.user.orgId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST create new door user */
router.post('/', async (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
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

        const result = await pool.query(
            'INSERT INTO door_users (name, org_id) VALUES ($1, $2) RETURNING *',
            [name.trim(), orgId]
        );
        await audit(req, 'doorUser.create', { targetType: 'door_user', targetId: result.rows[0].id, orgId, details: { name: name.trim() } });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* PATCH toggle user active/inactive */
router.patch('/:id/active', async (req, res) => {
    const { active } = req.body;
    if (active === undefined) return res.status(400).json({ error: 'active required' });
    try {
        const du = await getDoorUser(req, req.params.id);
        if (!du) return res.status(404).json({ error: 'User not found' });

        const result = await pool.query(
            'UPDATE door_users SET active = $1 WHERE id = $2 RETURNING *',
            [active, du.id]
        );
        await audit(req, 'doorUser.setActive', { targetType: 'door_user', targetId: du.id, orgId: du.org_id, details: { active: !!active } });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE door user */
router.delete('/:id', async (req, res) => {
    try {
        const du = await getDoorUser(req, req.params.id);
        if (!du) return res.status(404).json({ error: 'User not found' });

        await pool.query('DELETE FROM door_users WHERE id = $1', [du.id]);
        await audit(req, 'doorUser.delete', { targetType: 'door_user', targetId: du.id, orgId: du.org_id, details: { name: du.name } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET credentials for a user */
router.get('/:id/credentials', async (req, res) => {
    try {
        const du = await getDoorUser(req, req.params.id);
        if (!du) return res.status(404).json({ error: 'User not found' });

        const result = await pool.query(
            `SELECT uc.*, d.name AS device_name, d.serial, d.mqtt_id
             FROM user_credentials uc
             JOIN devices d ON d.id = uc.device_id
             WHERE uc.user_id = $1
             ORDER BY uc.created_at DESC`,
            [du.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST add credential to user + send MQTT to device */
router.post('/:id/credentials', async (req, res) => {
    const { device_id, type, identifier } = req.body;
    if (!device_id || !type || !identifier)
        return res.status(400).json({ error: 'device_id, type, identifier required' });
    if (!['rfid', 'pin', 'qr'].includes(type))
        return res.status(400).json({ error: 'type must be rfid, pin, or qr' });

    try {
        const du = await getDoorUser(req, req.params.id);
        if (!du) return res.status(404).json({ error: 'User not found' });
        const userName = du.name;

        /* The device must be one the caller may access ... */
        const device = await getAccessibleDevice(req.user, device_id);
        if (!device) return res.status(404).json({ error: 'Device not found' });

        /* ... and must belong to the same customer as the door user, so a
           person of customer A can never be enrolled on customer B's door. */
        if (!sameOrg(device.org_id, du.org_id))
            return res.status(400).json({ error: 'This user and this device belong to different customers' });

        const mqttId = device.mqtt_id || device.serial;

        /* Save to DB — identifier = user name (matches what firmware sends), cred_data = actual UID/PIN */
        const result = await pool.query(
            `INSERT INTO user_credentials (user_id, device_id, type, identifier, cred_data)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [du.id, device.id, type, userName, identifier.trim()]
        );

        /* Send MQTT command to device */
        const payload = buildCommand(device, 'add_credential', {
            cred_type: type,
            cred_data: identifier.trim(),  /* actual PIN/UID/QR value for the device */
            label:     userName,           /* name shown in logs */
            duress:    'false'
        });

        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

        await audit(req, 'doorUser.credential.add', {
            targetType: 'door_user', targetId: du.id, orgId: du.org_id,
            details: { device_id: device.id, type }
        });

        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505')
            return res.status(409).json({ error: 'This credential is already assigned on this device', code: '23505' });
        res.status(500).json({ error: err.message });
    }
});

/* DELETE credential + send MQTT to device */
router.delete('/credentials/:id', async (req, res) => {
    try {
        /* Get credential info before deleting */
        const credResult = await pool.query(
            `SELECT uc.*, d.mqtt_id, d.serial, du.name AS user_name
             FROM user_credentials uc
             JOIN devices d ON d.id = uc.device_id
             JOIN door_users du ON du.id = uc.user_id
             WHERE uc.id = $1`,
            [req.params.id]
        );

        if (credResult.rows.length === 0)
            return res.status(404).json({ error: 'Credential not found' });

        const cred = credResult.rows[0];

        /* Caller must own both the door user and the device (else 404) */
        const du     = await getDoorUser(req, cred.user_id);
        const device = await getAccessibleDevice(req.user, cred.device_id);
        if (!du || !device)
            return res.status(404).json({ error: 'Credential not found' });

        const mqttId = cred.mqtt_id || cred.serial;

        /* Delete from DB */
        await pool.query('DELETE FROM user_credentials WHERE id = $1', [cred.id]);

        /* Send MQTT delete_credential to device */
        const payload = buildCommand(device, 'delete_credential', { label: cred.user_name });

        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

        await audit(req, 'doorUser.credential.delete', {
            targetType: 'door_user', targetId: du.id, orgId: du.org_id,
            details: { device_id: device.id, type: cred.type }
        });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
