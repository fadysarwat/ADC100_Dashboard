const express     = require('express');
const router      = express.Router();
const pool        = require('../db/pool');
const { publish } = require('../mqtt');
const crypto      = require('crypto');
require('dotenv').config();

function generateHmac(cmd, ts) {
    return crypto.createHmac('sha256', process.env.MQTT_SECRET)
                 .update(`${cmd}:${ts}`)
                 .digest('hex');
}

function generatePin() {
    return String(Math.floor(1000 + Math.random() * 9000));
}

/* GET all temp pins for a device */
router.get('/:deviceId', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM temp_pins WHERE device_id = $1 ORDER BY created_at DESC',
            [req.params.deviceId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST add temp pin */
router.post('/:deviceId', async (req, res) => {
    const { label, iat, exp, pin } = req.body;
    if (!iat || !exp)
        return res.status(400).json({ error: 'iat and exp required' });

    try {
        /* Get device */
        const devResult = await pool.query(
            'SELECT * FROM devices WHERE id = $1',
            [req.params.deviceId]
        );
        if (devResult.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });

        const device   = devResult.rows[0];
        const finalPin = pin || generatePin();
        const pinLabel = label || `temp_${finalPin}`;

        /* Save to DB */
        const result = await pool.query(
            `INSERT INTO temp_pins (device_id, pin, label, iat, exp, active)
             VALUES ($1, $2, $3, $4, $5, TRUE) RETURNING *`,
            [req.params.deviceId, finalPin, pinLabel, new Date(iat), new Date(exp)]
        );

        /* Send add_credential to Controller via MQTT */
        const ts   = Math.floor(Date.now() / 1000);
        const hmac = generateHmac('add_credential', ts);
        const mqtt_id = device.mqtt_id || device.serial;

        const payload = {
            cmd:       'add_credential',
            ts,
            hmac,
            cred_type: 'pin',
            cred_data: finalPin,
            label:     pinLabel,
            duress:    'false'
        };
        publish(`adc100/${mqtt_id}/cmd`, JSON.stringify(payload));

        res.json({ ...result.rows[0], pin: finalPin });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE temp pin — removes from Controller too */
router.delete('/:deviceId/:pinId', async (req, res) => {
    try {
        /* Get pin info */
        const pinResult = await pool.query(
            'SELECT * FROM temp_pins WHERE id = $1 AND device_id = $2',
            [req.params.pinId, req.params.deviceId]
        );
        if (pinResult.rows.length === 0)
            return res.status(404).json({ error: 'Pin not found' });

        const pin = pinResult.rows[0];

        /* Get device */
        const devResult = await pool.query(
            'SELECT * FROM devices WHERE id = $1',
            [req.params.deviceId]
        );
        const device  = devResult.rows[0];
        const mqtt_id = device.mqtt_id || device.serial;

        /* Delete from DB */
        await pool.query('DELETE FROM temp_pins WHERE id = $1', [req.params.pinId]);

        /* Send delete_credential to Controller */
        const ts   = Math.floor(Date.now() / 1000);
        const hmac = generateHmac('delete_credential', ts);

        const payload = {
            cmd:   'delete_credential',
            ts,
            hmac,
            label: pin.label
        };
        publish(`adc100/${mqtt_id}/cmd`, JSON.stringify(payload));

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;