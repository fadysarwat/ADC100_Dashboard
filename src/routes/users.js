const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { publish } = require('../mqtt');
const crypto  = require('crypto');
require('dotenv').config();

/* GET all door users */
router.get('/', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM door_users ORDER BY name ASC'
        );
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
        const result = await pool.query(
            'INSERT INTO door_users (name) VALUES ($1) RETURNING *',
            [name.trim()]
        );
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
        const result = await pool.query(
            'UPDATE door_users SET active = $1 WHERE id = $2 RETURNING *',
            [active, req.params.id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE door user */
router.delete('/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM door_users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET credentials for a user */
router.get('/:id/credentials', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT uc.*, d.name AS device_name, d.serial, d.mqtt_id
             FROM user_credentials uc
             JOIN devices d ON d.id = uc.device_id
             WHERE uc.user_id = $1
             ORDER BY uc.created_at DESC`,
            [req.params.id]
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
        /* Get user name */
        const userResult = await pool.query(
            'SELECT name FROM door_users WHERE id = $1',
            [req.params.id]
        );
        if (userResult.rows.length === 0)
            return res.status(404).json({ error: 'User not found' });
        const userName = userResult.rows[0].name;

        /* Get device mqtt_id */
        const devResult = await pool.query(
            'SELECT mqtt_id, serial FROM devices WHERE id = $1',
            [device_id]
        );
        if (devResult.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });
        const mqttId = devResult.rows[0].mqtt_id || devResult.rows[0].serial;

        /* Save to DB — identifier = user name (matches what firmware sends), cred_data = actual UID/PIN */
        const result = await pool.query(
            `INSERT INTO user_credentials (user_id, device_id, type, identifier, cred_data)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [req.params.id, device_id, type, userName, identifier.trim()]
        );

        /* Send MQTT command to device */
        const ts      = Math.floor(Date.now() / 1000);
        const message = `add_credential:${ts}`;
        const hmac    = crypto.createHmac('sha256', process.env.MQTT_SECRET)
                              .update(message)
                              .digest('hex');

        const payload = {
            cmd:       'add_credential',
            ts,
            hmac,
            cred_type: type,
            cred_data: identifier.trim(),  /* actual PIN/UID/QR value for the device */
            label:     userName,           /* name shown in logs */
            duress:    'false'
        };

        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

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

        const cred   = credResult.rows[0];
        const mqttId = cred.mqtt_id || cred.serial;

        /* Delete from DB */
        await pool.query('DELETE FROM user_credentials WHERE id = $1', [req.params.id]);

        /* Send MQTT delete_credential to device */
        const ts      = Math.floor(Date.now() / 1000);
        const message = `delete_credential:${ts}`;
        const hmac    = crypto.createHmac('sha256', process.env.MQTT_SECRET)
                              .update(message)
                              .digest('hex');

        const payload = {
            cmd:   'delete_credential',
            ts,
            hmac,
            label: cred.user_name
        };

        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;