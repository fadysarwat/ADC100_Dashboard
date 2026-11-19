const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
require('dotenv').config();

/* No hard-coded fallback in production: a known secret would let anyone forge app tokens. */
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
    console.error('FATAL: JWT_SECRET must be set in production.');
    process.exit(1);
}
const JWT_SECRET  = process.env.JWT_SECRET || 'dev-only-jwt-secret-not-for-production';
const JWT_EXPIRES = '30d';

/* ── POST /api/app/login ── */
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'username and password required' });

    try {
        /* 1. Find user */
        /* Disabled user, or user of a disabled customer, cannot log in */
        const userResult = await pool.query(
            `SELECT u.* FROM app_users u
               LEFT JOIN organizations o ON o.id = u.org_id
              WHERE u.username = $1 AND u.is_active = TRUE
                AND (u.org_id IS NULL OR o.is_active = TRUE)`,
            [username]
        );
        if (userResult.rows.length === 0)
            return res.status(401).json({ error: 'Invalid credentials' });

        const user = userResult.rows[0];

        /* 2. Verify password */
        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ error: 'Invalid credentials' });

        /* 3. Get accessible doors */
        const doorsResult = await pool.query(
            `SELECT d.id, d.mqtt_id, d.name, d.location, d.ble_name
             FROM user_door_access uda
             JOIN devices d ON d.id = uda.device_id
             WHERE uda.user_id = $1`,
            [user.id]
        );

        /* 4. Build keys map: { mqtt_id: ble_secret } */
        const keys = {};
        doorsResult.rows.forEach(door => {
            const doorId = door.mqtt_id || String(door.id);
            keys[doorId] = process.env.BLE_SECRET || 'ADC100-DEFAULT-KEY';
        });

        const doors = doorsResult.rows.map(d => ({
            id:       d.id,
            mqtt_id:  d.mqtt_id,
            name:     d.name     || 'Unnamed',
            location: d.location || '—',
            ble_name: d.ble_name || `ADC100-${d.mqtt_id}`
        }));

        /* 5. Generate JWT */
        const token = jwt.sign(
            { user_id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES }
        );

        res.json({
            token,
            user: { id: user.id, username: user.username, full_name: user.full_name },
            doors,
            keys,
            keys_updated_at: new Date().toISOString()   // ← timestamp
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ── GET /api/app/keys ── (refresh keys with valid token) ── */
router.get('/keys', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer '))
        return res.status(401).json({ error: 'No token provided' });

    const token = auth.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        /* A valid token is not enough: the user (and its customer) must still be
           active, otherwise a disabled user keeps receiving keys until the
           30-day token expires. */
        const stillActive = await pool.query(
            `SELECT 1 FROM app_users u
               LEFT JOIN organizations o ON o.id = u.org_id
              WHERE u.id = $1 AND u.is_active = TRUE
                AND (u.org_id IS NULL OR o.is_active = TRUE)`,
            [decoded.user_id]
        );
        if (stillActive.rows.length === 0)
            return res.status(401).json({ error: 'Invalid or expired token' });

        const doorsResult = await pool.query(
            `SELECT d.id, d.mqtt_id, d.name, d.location, d.ble_name
             FROM user_door_access uda
             JOIN devices d ON d.id = uda.device_id
             WHERE uda.user_id = $1`,
            [decoded.user_id]
        );

        const keys = {};
        doorsResult.rows.forEach(door => {
            const doorId = door.mqtt_id || String(door.id);
            keys[doorId] = process.env.BLE_SECRET || 'ADC100-DEFAULT-KEY';
        });

        const doors = doorsResult.rows.map(d => ({
            id:       d.id,
            mqtt_id:  d.mqtt_id,
            name:     d.name     || 'Unnamed',
            location: d.location || '—',
            ble_name: d.ble_name || `ADC100-${d.mqtt_id}`
        }));

        res.json({
            doors,
            keys,
            keys_updated_at: new Date().toISOString()   // ← timestamp
        });

    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

module.exports = router;