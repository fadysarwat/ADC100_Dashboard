const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { publish } = require('../mqtt');
const crypto  = require('crypto');
const { requireDevice, hasPerm } = require('../auth');
const { audit } = require('../audit');
require('dotenv').config();

function generateHmac(cmd, ts) {
    return crypto.createHmac('sha256', process.env.MQTT_SECRET)
                 .update(`${cmd}:${ts}`)
                 .digest('hex');
}

/* Every route below is scoped to ONE device. requireDevice() checks both the
   role permission and that the device belongs to the caller's customer
   (otherwise 404), and exposes the device as req.device. */

/* GET all credentials for a device.
   Roles that can only VIEW (not manage) never receive the secret itself. */
router.get('/:deviceId', requireDevice('credentials.view', 'deviceId'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM credentials WHERE device_id = $1 ORDER BY created_at DESC',
            [req.device.id]
        );
        const canSeeSecrets = hasPerm(req.user.role, 'credentials.manage');
        res.json(canSeeSecrets
            ? result.rows
            : result.rows.map(r => ({ ...r, cred_data: '••••' })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST add credential */
router.post('/:deviceId', requireDevice('credentials.manage', 'deviceId'), async (req, res) => {
    const { label, cred_type, cred_data, is_duress } = req.body;
    if (!label || !cred_type || !cred_data)
        return res.status(400).json({ error: 'label, cred_type, cred_data required' });

    try {
        const device = req.device;

        /* Save to DB */
        const result = await pool.query(
            `INSERT INTO credentials (device_id, label, cred_type, cred_data, is_duress, is_active)
             VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING *`,
            [device.id, label, cred_type, cred_data, is_duress || false]
        );

        const mqttId = device.mqtt_id || device.serial;
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
        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

        await audit(req, 'credential.add', {
            targetType: 'device', targetId: device.id, orgId: device.org_id,
            details: { label, cred_type, duress: !!is_duress }
        });

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE credential */
router.delete('/:deviceId/:credId', requireDevice('credentials.manage', 'deviceId'), async (req, res) => {
    try {
        const device = req.device;

        /* The credential must belong to THIS device (already a customer-owned one) */
        const credResult = await pool.query(
            'SELECT * FROM credentials WHERE id = $1 AND device_id = $2',
            [req.params.credId, device.id]
        );
        if (credResult.rows.length === 0)
            return res.status(404).json({ error: 'Credential not found' });

        const cred = credResult.rows[0];

        /* Delete from DB */
        await pool.query('DELETE FROM credentials WHERE id = $1', [cred.id]);

        const mqttId = device.mqtt_id || device.serial;
        const ts     = Math.floor(Date.now() / 1000);
        const hmac   = generateHmac('delete_credential', ts);

        /* Send MQTT command */
        const payload = {
            cmd:   'delete_credential',
            ts,
            hmac,
            label: cred.label
        };
        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));

        await audit(req, 'credential.delete', {
            targetType: 'device', targetId: device.id, orgId: device.org_id,
            details: { label: cred.label, cred_type: cred.cred_type }
        });

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
