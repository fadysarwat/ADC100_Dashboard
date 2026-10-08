const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const bcrypt  = require('bcrypt');
require('dotenv').config();

/* GET all app users */
router.get('/', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.username, u.full_name, u.is_active, u.created_at,
                    COUNT(uda.device_id) as door_count
             FROM app_users u
             LEFT JOIN user_door_access uda ON uda.user_id = u.id
             GROUP BY u.id ORDER BY u.created_at DESC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET user doors */
router.get('/:id/doors', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT d.id, d.mqtt_id, d.name, d.location
             FROM user_door_access uda
             JOIN devices d ON d.id = uda.device_id
             WHERE uda.user_id = $1`,
            [req.params.id]
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
        const hash   = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO app_users (username, password, full_name) VALUES ($1, $2, $3) RETURNING id, username, full_name, is_active, created_at',
            [username, hash, full_name || '']
        );
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
        const result = await pool.query(
            'UPDATE app_users SET is_active = NOT is_active WHERE id = $1 RETURNING *',
            [req.params.id]
        );
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
        await pool.query(
            'INSERT INTO user_door_access (user_id, device_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [req.params.id, device_id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE revoke door access */
router.delete('/:id/doors/:deviceId', async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM user_door_access WHERE user_id = $1 AND device_id = $2',
            [req.params.id, req.params.deviceId]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* DELETE app user */
router.delete('/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM app_users WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;