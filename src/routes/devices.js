const express     = require('express');
const router      = express.Router();
const pool        = require('../db/pool');
const { publish } = require('../mqtt');
const crypto      = require('crypto');
require('dotenv').config();

/* Generate unique serial number */
function generateSerial() {
    const date   = new Date();
    const year   = date.getFullYear();
    const month  = String(date.getMonth() + 1).padStart(2, '0');
    const day    = String(date.getDate()).padStart(2, '0');
    const random = Math.random().toString(36).toUpperCase().substring(2, 6);
    return `ADC100-${year}${month}${day}-${random}`;
}

/* GET all devices */
router.get('/', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM devices ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST generate new serial */
router.post('/generate-serial', async (req, res) => {
    try {
        let serial;
        let exists = true;
        while (exists) {
            serial = generateSerial();
            const check = await pool.query(
                'SELECT id FROM serials WHERE serial = $1',
                [serial]
            );
            exists = check.rows.length > 0;
        }
        await pool.query('INSERT INTO serials (serial) VALUES ($1)', [serial]);
        res.json({ serial });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET all serials */
router.get('/serials', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM serials ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST generate temporary QR */
router.post('/temp-qr', async (req, res) => {
    const { iat, exp } = req.body;
    if (!iat || !exp)
        return res.status(400).json({ error: 'iat and exp required' });

    try {
        const iatTs = Math.floor(new Date(iat).getTime() / 1000);
        const expTs = Math.floor(new Date(exp).getTime() / 1000);

        if (expTs <= iatTs)
            return res.status(400).json({ error: 'exp must be after iat' });

        const message = `temp_qr:${iatTs}:${expTs}`;
        const hmac    = crypto.createHmac('sha256', process.env.MQTT_SECRET)
                              .update(message)
                              .digest('hex');

        const token = JSON.stringify({ iat: iatTs, exp: expTs, hmac });
        res.json({ token, iat: iatTs, exp: expTs });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST add new device */
router.post('/', async (req, res) => {
    const { serial, mqtt_id, name, location } = req.body;
    if (!serial) return res.status(400).json({ error: 'Serial required' });
    try {
        const serialCheck = await pool.query(
            'SELECT id FROM serials WHERE serial = $1',
            [serial]
        );
        if (serialCheck.rows.length === 0)
            return res.status(400).json({ error: 'Serial not found — generate it first' });

        const result = await pool.query(
            'INSERT INTO devices (serial, mqtt_id, name, location, status, activated) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [serial, mqtt_id || '', name || '', location || '', 'offline', false]
        );

        await pool.query(
            'UPDATE serials SET device_id = $1, assigned_at = NOW() WHERE serial = $2',
            [result.rows[0].id, serial]
        );

        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST activate device manually */
router.post('/:id/activate', async (req, res) => {
    try {
        const result = await pool.query(
            'UPDATE devices SET activated = TRUE WHERE id = $1 RETURNING *',
            [req.params.id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* PATCH update device notes */
router.patch('/:id/notes', async (req, res) => {
    const { notes } = req.body;
    try {
        const result = await pool.query(
            'UPDATE devices SET notes = $1 WHERE id = $2 RETURNING *',
            [notes || '', req.params.id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* PATCH update relay settings */
router.patch('/:id/relay', async (req, res) => {
    const { relay_mode, relay_duration } = req.body;

    if (!relay_mode || !['timed', 'latched'].includes(relay_mode))
        return res.status(400).json({ error: 'relay_mode must be timed or latched' });

    if (relay_mode === 'timed') {
        const dur = parseInt(relay_duration);
        if (isNaN(dur) || dur < 1 || dur > 300)
            return res.status(400).json({ error: 'relay_duration must be 1–300 seconds' });
    }

    try {
        const result = await pool.query(
            'UPDATE devices SET relay_mode = $1, relay_duration = $2 WHERE id = $3 RETURNING *',
            [relay_mode, relay_mode === 'timed' ? parseInt(relay_duration) : null, req.params.id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE device */
router.delete('/:id', async (req, res) => {
    try {
        await pool.query(
            'UPDATE serials SET device_id = NULL, assigned_at = NULL WHERE device_id = $1',
            [req.params.id]
        );
        await pool.query('DELETE FROM devices WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET device heartbeats */
router.get('/:id/heartbeats', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM heartbeats WHERE device_id = $1 ORDER BY created_at DESC LIMIT 1',
            [req.params.id]
        );
        res.json(result.rows[0] || null);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET device access logs with filters */
router.get('/:id/logs', async (req, res) => {
    try {
        const { method, result, from, to } = req.query;

        let query  = 'SELECT * FROM access_logs WHERE device_id = $1';
        let params = [req.params.id];
        let idx    = 2;

        if (method) {
            query += ` AND method = $${idx++}`;
            params.push(method);
        }
        if (result) {
            query += ` AND result = $${idx++}`;
            params.push(result);
        }
        if (from) {
            query += ` AND created_at >= $${idx++}`;
            params.push(new Date(from));
        }
        if (to) {
            query += ` AND created_at <= $${idx++}`;
            params.push(new Date(to));
        }

        query += ' ORDER BY created_at DESC LIMIT 200';

        const dbResult = await pool.query(query, params);
        res.json(dbResult.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET export access logs as CSV */
router.get('/:id/logs/export', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM access_logs WHERE device_id = $1 ORDER BY created_at DESC',
            [req.params.id]
        );
        const header = 'ID,Method,Result,Time\n';
        const csv    = result.rows.map(r =>
            `${r.id},${r.method},${r.result},"${new Date(r.created_at).toLocaleString()}"`
        ).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="logs_device_${req.params.id}.csv"`);
        res.send(header + csv);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST send command to device */
router.post('/command', async (req, res) => {
    const { serial, cmd, ts, enabled, start, end, name } = req.body;
    if (!serial || !cmd || !ts)
        return res.status(400).json({ error: 'serial, cmd, ts required' });

    try {
        const devResult = await pool.query(
            'SELECT id, mqtt_id, relay_mode, relay_duration FROM devices WHERE serial = $1',
            [serial]
        );
        if (devResult.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });

        const { id: deviceId, mqtt_id, relay_mode, relay_duration } = devResult.rows[0];
        const mqttId  = mqtt_id || serial;
        const message = `${cmd}:${ts}`;
        const hmac    = crypto.createHmac('sha256', process.env.MQTT_SECRET)
                              .update(message)
                              .digest('hex');

        const payload = { cmd, ts, hmac };

        if (cmd === 'open') {
            payload.relay_mode = relay_mode || 'timed';
            if ((relay_mode || 'timed') === 'timed') {
                payload.relay_duration = relay_duration || 5;
            }
        }

        if (cmd === 'set_schedule') {
            payload.enabled = enabled;
            payload.start   = start;
            payload.end     = end;
        }

        if (cmd === 'set_touch') {
            if (enabled === undefined || enabled === null)
                return res.status(400).json({ error: 'enabled required for set_touch' });
            payload.enabled = enabled;
        }

        if (cmd === 'ota_update') {
            const { url } = req.body;
            if (!url) return res.status(400).json({ error: 'url required for ota_update' });
            payload.url = url;
        }

        if (cmd === 'set_ble_name') {
            if (!name) return res.status(400).json({ error: 'name required for set_ble_name' });
            if (!name.startsWith('ADC100-'))
                return res.status(400).json({ error: 'BLE name must start with ADC100-' });
            payload.name = name;

            await pool.query(
                'UPDATE devices SET ble_name = $1 WHERE id = $2',
                [name, deviceId]
            );
        }

        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;