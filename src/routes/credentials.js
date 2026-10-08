const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { publish } = require('../mqtt');
const crypto  = require('crypto');
require('dotenv').config();

function generateHmac(cmd, ts) {
    return crypto.createHmac('sha256', process.env.MQTT_SECRET)
                 .update(`${cmd}:${ts}`)
                 .digest('hex');
}

/* GET all credentials for a device */
router.get('/:deviceId', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM credentials WHERE device_id = $1 ORDER BY created_at DESC',
            [req.params.deviceId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST add credential */
router.post('/:deviceId', async (req, res) => {
    const { label, cred_type, cred_data, is_duress } = req.body;
    if (!label || !cred_type || !cred_data)
        return res.status(400).json({ error: 'label, cred_type, cred_data required' });

    try {
        /* Save to DB */
        const result = await pool.query(
            `INSERT INTO credentials (device_id, label, cred_type, cred_data, is_duress, is_active)
             VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING *`,
            [req.params.deviceId, label, cred_type, cred_data, is_duress || false]
        );

        /* Get device serial */
        const devResult = await pool.query(
            'SELECT serial FROM devices WHERE id = $1',
            [req.params.deviceId]
        );
        if (devResult.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });

        const serial = devResult.rows[0].serial;
        const ts     = Math.floor(Date.now() / 1000);
        const hmac   = generateHmac('add_credential', ts);

        /* Send MQTT command */
        const payload = {
            cmd:       'add_credential',
            ts,
            hmac,
            cred_type,
            cred_data,
            label,
            duress:    is_duress ? 'true' : 'false'
        };
        publish(`adc100/${serial}/cmd`, JSON.stringify(payload));

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE credential */
router.delete('/:deviceId/:credId', async (req, res) => {
    try {
        /* Get credential info */
        const credResult = await pool.query(
            'SELECT * FROM credentials WHERE id = $1 AND device_id = $2',
            [req.params.credId, req.params.deviceId]
        );
        if (credResult.rows.length === 0)
            return res.status(404).json({ error: 'Credential not found' });

        const cred = credResult.rows[0];

        /* Delete from DB */
        await pool.query('DELETE FROM credentials WHERE id = $1', [req.params.credId]);

        /* Get device serial */
        const devResult = await pool.query(
            'SELECT serial FROM devices WHERE id = $1',
            [req.params.deviceId]
        );
        const serial = devResult.rows[0].serial;
        const ts     = Math.floor(Date.now() / 1000);
        const hmac   = generateHmac('delete_credential', ts);

        /* Send MQTT command */
        const payload = {
            cmd:   'delete_credential',
            ts,
            hmac,
            label: cred.label
        };
        publish(`adc100/${serial}/cmd`, JSON.stringify(payload));

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;