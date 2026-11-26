const express     = require('express');
const router      = express.Router();
const pool        = require('../db/pool');
const { publish } = require('../mqtt');
const crypto      = require('crypto');
const { deviceScope, requirePerm, requireDevice, getAccessibleDevice, hasPerm } = require('../auth');
const { audit }   = require('../audit');
const { buildCommand, temporaryQr, provisionBundle, buildProvisionCommand } = require('../devicesig');
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

/* GET devices — only the ones the caller is allowed to see */
router.get('/', async (req, res) => {
    try {
        const scope  = deviceScope(req.user, 'd', 1);
        const result = await pool.query(
            `SELECT d.*, o.name AS org_name
               FROM devices d
               LEFT JOIN organizations o ON o.id = d.org_id
              WHERE ${scope.clause}
              ORDER BY d.created_at DESC`,
            scope.params
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST generate new serial */
router.post('/generate-serial', requirePerm('serials.manage'), async (req, res) => {
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
router.get('/serials', requirePerm('serials.manage'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM serials ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST generate temporary QR
   PLATFORM-ONLY for now. The token is signed with the single MQTT_SECRET and
   is not bound to a device, so a QR generated for one customer would open the
   doors of every customer. It can be opened to customers once the firmware
   verifies a device-bound token (device id inside the signed message). */
router.post('/temp-qr', requirePerm('qr.global'), async (req, res) => {
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
router.post('/', requirePerm('device.create'), async (req, res) => {
    const { serial, mqtt_id, name, location } = req.body;
    if (!serial) return res.status(400).json({ error: 'Serial required' });
    try {
        /* Optional owner (customer). Omitted = unassigned. */
        let orgId = null;
        if (req.body.org_id !== undefined && req.body.org_id !== null && req.body.org_id !== '') {
            orgId = parseInt(req.body.org_id, 10);
            const orgCheck = Number.isInteger(orgId)
                ? await pool.query('SELECT id FROM organizations WHERE id = $1', [orgId])
                : { rows: [] };
            if (orgCheck.rows.length === 0)
                return res.status(400).json({ error: 'Customer (org_id) not found' });
        }

        const serialCheck = await pool.query(
            'SELECT id FROM serials WHERE serial = $1',
            [serial]
        );
        if (serialCheck.rows.length === 0)
            return res.status(400).json({ error: 'Serial not found — generate it first' });

        const result = await pool.query(
            'INSERT INTO devices (serial, mqtt_id, name, location, status, activated, org_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [serial, mqtt_id || '', name || '', location || '', 'offline', false, orgId]
        );

        await pool.query(
            'UPDATE serials SET device_id = $1, assigned_at = NOW() WHERE serial = $2',
            [result.rows[0].id, serial]
        );

        await audit(req, 'device.create', { targetType: 'device', targetId: result.rows[0].id, orgId, details: { serial } });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST activate device manually (platform-only) */
router.post('/:id/activate', requireDevice('device.activate'), async (req, res) => {
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

/* PATCH assign a device to a customer (platform-only).
   Body: { org_id: <id> | null }

   - First assignment (device has no owner): allowed. Door users / mobile users
     that have no customer yet but already use this device are adopted by the
     customer, so existing data keeps working.
   - Moving to another customer, or unassigning: refused while anything
     customer-specific is still attached (credentials, temp PINs, door-user
     credentials, mobile access, dashboard door restrictions) because those
     belong to the previous customer. Remove them first. */
router.patch('/:id/org', requireDevice('device.assign'), async (req, res) => {
    try {
        const dev = req.device;

        let newOrg = null;
        if (req.body.org_id !== undefined && req.body.org_id !== null && req.body.org_id !== '') {
            newOrg = parseInt(req.body.org_id, 10);
            const o = Number.isInteger(newOrg)
                ? await pool.query('SELECT id FROM organizations WHERE id = $1', [newOrg])
                : { rows: [] };
            if (o.rows.length === 0)
                return res.status(400).json({ error: 'Customer (org_id) not found' });
        }

        if ((dev.org_id ?? null) === newOrg) return res.json(dev);

        if (dev.org_id !== null) {
            const counts = [];
            const countOf = async (label, sql) => {
                try {
                    const r = await pool.query(sql, [dev.id]);
                    if (r.rows[0].n > 0) counts.push(`${label}: ${r.rows[0].n}`);
                } catch (e) { /* table not present on this database */ }
            };
            await countOf('credentials',            'SELECT COUNT(*)::int AS n FROM credentials WHERE device_id = $1');
            await countOf('temp PINs',              'SELECT COUNT(*)::int AS n FROM temp_pins WHERE device_id = $1');
            await countOf('door-user credentials',  'SELECT COUNT(*)::int AS n FROM user_credentials WHERE device_id = $1');
            await countOf('mobile access',          'SELECT COUNT(*)::int AS n FROM user_door_access WHERE device_id = $1');
            await countOf('dashboard door restrictions', 'SELECT COUNT(*)::int AS n FROM dashboard_user_device_access WHERE device_id = $1');
            if (counts.length > 0)
                return res.status(409).json({ error: 'Remove the previous customer\'s data from this device first (' + counts.join(', ') + ')' });
        }

        const result = await pool.query(
            'UPDATE devices SET org_id = $1 WHERE id = $2 RETURNING *',
            [newOrg, dev.id]
        );

        let adopted = { door_users: 0, app_users: 0 };
        if (dev.org_id === null && newOrg !== null) {
            try {
                const a = await pool.query(
                    `UPDATE door_users SET org_id = $1
                      WHERE org_id IS NULL
                        AND id IN (SELECT user_id FROM user_credentials WHERE device_id = $2)`,
                    [newOrg, dev.id]);
                const b = await pool.query(
                    `UPDATE app_users SET org_id = $1
                      WHERE org_id IS NULL
                        AND id IN (SELECT user_id FROM user_door_access WHERE device_id = $2)`,
                    [newOrg, dev.id]);
                adopted = { door_users: a.rowCount, app_users: b.rowCount };
            } catch (e) {
                console.warn('assign: could not adopt existing users:', e.message);
            }
        }

        if (req.app.locals.hub) req.app.locals.hub.invalidateDevice(dev.id);

        await audit(req, 'device.assign', {
            targetType: 'device', targetId: dev.id, orgId: newOrg,
            details: { from: dev.org_id, to: newOrg, adopted }
        });
        res.json({ ...result.rows[0], adopted });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* PATCH update device notes */
router.patch('/:id/notes', requireDevice('device.configure'), async (req, res) => {
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
router.patch('/:id/relay', requireDevice('device.configure'), async (req, res) => {
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
router.delete('/:id', requireDevice('device.delete'), async (req, res) => {
    try {
        await pool.query(
            'UPDATE serials SET device_id = NULL, assigned_at = NULL WHERE device_id = $1',
            [req.params.id]
        );
        await pool.query('DELETE FROM devices WHERE id = $1', [req.params.id]);
        await audit(req, 'device.delete', { targetType: 'device', targetId: req.params.id, orgId: req.device.org_id, details: { serial: req.device.serial } });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET device heartbeats */
router.get('/:id/heartbeats', requireDevice('device.view'), async (req, res) => {
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

/* GET outage history (when the device went offline, when it came back) */
router.get('/:id/outages', requireDevice('device.view'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, started_at, ended_at,
                    EXTRACT(EPOCH FROM (COALESCE(ended_at, NOW()) - started_at))::int AS seconds
               FROM device_outages
              WHERE device_id = $1
              ORDER BY started_at DESC
              LIMIT 50`,
            [req.params.id]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET device access logs with filters */
router.get('/:id/logs', requireDevice('logs.view'), async (req, res) => {
    try {
        const { method, result, from, to } = req.query;

        let query  = `SELECT al.*, du.name AS user_name
                      FROM access_logs al
                      LEFT JOIN door_users du ON du.id = al.door_user_id
                      WHERE al.device_id = $1`;
        let params = [req.params.id];
        let idx    = 2;

        if (method) {
            query += ` AND al.method = $${idx++}`;
            params.push(method);
        }
        if (result) {
            query += ` AND al.result = $${idx++}`;
            params.push(result);
        }
        if (from) {
            query += ` AND al.created_at >= $${idx++}`;
            params.push(new Date(from));
        }
        if (to) {
            query += ` AND al.created_at <= $${idx++}`;
            params.push(new Date(to));
        }

        query += ' ORDER BY al.created_at DESC LIMIT 200';

        const dbResult = await pool.query(query, params);
        res.json(dbResult.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET export access logs as CSV */
router.get('/:id/logs/export', requireDevice('logs.export'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT al.*, du.name AS user_name
             FROM access_logs al
             LEFT JOIN door_users du ON du.id = al.door_user_id
             WHERE al.device_id = $1
             ORDER BY al.created_at DESC`,
            [req.params.id]
        );
        const header = 'ID,Method,Result,User,Time\n';
        const csv    = result.rows.map(r =>
            `${r.id},${r.method},${r.result},"${r.user_name || '—'}","${new Date(r.created_at).toLocaleString()}"`
        ).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="logs_device_${req.params.id}.csv"`);
        res.send(header + csv);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* Which permission each device command needs.
   Deny-by-default: a command that is not listed needs 'device.ota', which
   only super_admin holds. */
const CMD_PERMS = {
    open:         'device.command',
    get_status:   'device.view',
    get_logs:     'logs.view',
    restart:      'device.configure',
    reset_wifi:   'device.configure',
    set_schedule: 'device.configure',
    set_touch:    'device.configure',
    set_wifi:     'device.configure',
    apply_wifi:   'device.configure',
    set_ble_name: 'device.configure',
    clear_logs:   'device.configure',
    ota_update:   'device.ota'
};

/* POST send command to device */
router.post('/command', async (req, res) => {
    const { serial, cmd, ts, enabled, start, end, name } = req.body;
    if (!serial || !cmd || !ts)
        return res.status(400).json({ error: 'serial, cmd, ts required' });

    try {
        const devResult = await pool.query(
            'SELECT id, serial, mqtt_id, relay_mode, relay_duration, key_version FROM devices WHERE serial = $1',
            [serial]
        );
        if (devResult.rows.length === 0)
            return res.status(404).json({ error: 'Device not found' });

        /* 1) the device must belong to the caller (404 hides other customers' devices)
           2) the caller's role must allow this specific command */
        const owned = await getAccessibleDevice(req.user, devResult.rows[0].id);
        if (!owned)
            return res.status(404).json({ error: 'Device not found' });
        if (!hasPerm(req.user.role, CMD_PERMS[cmd] || 'device.ota'))
            return res.status(403).json({ error: 'Forbidden' });

        const { id: deviceId, mqtt_id, relay_mode, relay_duration } = devResult.rows[0];
        const mqttId  = mqtt_id || serial;
        const fields  = {};

        if (cmd === 'open') {
            fields.relay_mode = relay_mode || 'timed';
            if ((relay_mode || 'timed') === 'timed') {
                fields.relay_duration = relay_duration || 5;
            }
        }

        if (cmd === 'set_schedule') {
            fields.enabled = enabled;
            fields.start   = start;
            fields.end     = end;
        }

        if (cmd === 'set_touch') {
            if (enabled === undefined || enabled === null)
                return res.status(400).json({ error: 'enabled required for set_touch' });
            fields.enabled = enabled;
        }

        if (cmd === 'ota_update') {
            const { url } = req.body;
            if (!url) return res.status(400).json({ error: 'url required for ota_update' });
            fields.url = url;
        }

        if (cmd === 'set_wifi') {
            const { ssid, password } = req.body;
            if (!ssid || !password)
                return res.status(400).json({ error: 'ssid and password required for set_wifi' });
            fields.ssid     = ssid;
            fields.pass     = password;   /* the firmware field is "pass" (was "password": never matched) */
        }

        if (cmd === 'apply_wifi') {
            /* No extra fields needed — device applies the pending credentials it already stored */
        }

        if (cmd === 'get_logs') {
            /* No extra fields needed — device responds on event topic with logs payload */
        }

        if (cmd === 'clear_logs') {
            /* No extra fields needed — device clears its log buffer */
        }

        if (cmd === 'set_ble_name') {
            if (!name) return res.status(400).json({ error: 'name required for set_ble_name' });
            if (!name.startsWith('ADC100-'))
                return res.status(400).json({ error: 'BLE name must start with ADC100-' });
            fields.name = name;

            await pool.query(
                'UPDATE devices SET ble_name = $1 WHERE id = $2',
                [name, deviceId]
            );
        }

        let payload;
        try {
            /* v2 devices: server time + nonce + per-device key; v1: legacy */
            const dev = devResult.rows[0];
            payload = buildCommand({ ...dev, mqtt_id: mqttId }, cmd, fields,
                                   (dev.key_version || 1) >= 2 ? {} : { ts });
        } catch (e) {
            return res.status(e.code === 'NO_MASTER_KEY' ? 500 : 400).json({ error: e.message });
        }
        publish(`adc100/${mqttId}/cmd`, JSON.stringify(payload));
        /* Never log secrets: only the command name and non-sensitive fields. */
        await audit(req, 'device.command', {
            targetType: 'device', targetId: deviceId, orgId: owned.org_id,
            details: { cmd, serial }
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ============================================================
   Device security (protocol v2) — see docs/PROTOCOL_V2.md
   ============================================================ */

/* POST export provisioning data of ONE device (platform admin only).
   Body (optional): { mqtt_uri, mqtt_user, mqtt_pass } to include in the NVS image.
   POST, not GET, so broker secrets never travel in a URL. */
router.post('/:id/provision', requirePerm('device.provision'), async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM devices WHERE id = $1', [parseInt(req.params.id, 10)]);
        if (!r.rows[0]) return res.status(404).json({ error: 'Device not found' });
        const bundle = provisionBundle(r.rows[0], {
            uri: req.body.mqtt_uri, user: req.body.mqtt_user, pass: req.body.mqtt_pass
        });
        await audit(req, 'device.provision.export', {
            targetType: 'device', targetId: r.rows[0].id, orgId: r.rows[0].org_id,
            details: { serial: r.rows[0].serial }          /* never the key */
        });
        res.json(bundle);
    } catch (err) {
        res.status(err.code === 'NO_MASTER_KEY' ? 500 : 400).json({ error: err.message });
    }
});

/* POST migrate a deployed (v1) device: sends the one-time provision command.
   The dashboard switches to v2 when the device confirms (see src/mqtt.js). */
router.post('/:id/migrate', requirePerm('device.provision'), async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM devices WHERE id = $1', [parseInt(req.params.id, 10)]);
        const dev = r.rows[0];
        if (!dev) return res.status(404).json({ error: 'Device not found' });
        if (dev.key_version >= 2) return res.status(409).json({ error: 'Device already uses protocol v2' });
        publish(`adc100/${dev.mqtt_id || dev.serial}/cmd`, JSON.stringify(buildProvisionCommand(dev)));
        await audit(req, 'device.migrate', {
            targetType: 'device', targetId: dev.id, orgId: dev.org_id, details: { serial: dev.serial }
        });
        res.json({ success: true, note: 'Command sent. The device switches to v2 once it confirms.' });
    } catch (err) {
        res.status(err.code === 'NO_MASTER_KEY' ? 500 : 400).json({ error: err.message });
    }
});

/* POST mark a factory-provisioned device as v2 (platform admin) */
router.post('/:id/mark-v2', requirePerm('device.provision'), async (req, res) => {
    try {
        const r = await pool.query('UPDATE devices SET key_version = 2 WHERE id = $1 RETURNING id, org_id, serial',
                                   [parseInt(req.params.id, 10)]);
        if (!r.rows[0]) return res.status(404).json({ error: 'Device not found' });
        await audit(req, 'device.mark_v2', { targetType: 'device', targetId: r.rows[0].id, orgId: r.rows[0].org_id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST temporary QR for ONE door (v2 devices). Body: { iat, exp } ISO dates. */
router.post('/:id/temp-qr', requireDevice('temppin.manage', 'id'), async (req, res) => {
    try {
        const dev = req.device;
        if ((dev.key_version || 1) < 2)
            return res.status(409).json({ error: 'This door has not been upgraded to the secure protocol yet' });
        const iat = Math.floor(new Date(req.body.iat).getTime() / 1000);
        const exp = Math.floor(new Date(req.body.exp).getTime() / 1000);
        if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp <= iat)
            return res.status(400).json({ error: 'valid iat and exp (exp after iat) required' });
        if (exp - iat > 7 * 24 * 3600)
            return res.status(400).json({ error: 'A temporary QR can be valid for at most 7 days' });
        const qr = temporaryQr(dev, iat, exp);
        await audit(req, 'device.tempqr', {
            targetType: 'device', targetId: dev.id, orgId: dev.org_id, details: { iat, exp }
        });
        res.json({ qr_text: qr, iat, exp });
    } catch (err) {
        res.status(err.code === 'NO_MASTER_KEY' ? 500 : 400).json({ error: err.message });
    }
});

module.exports = router;
