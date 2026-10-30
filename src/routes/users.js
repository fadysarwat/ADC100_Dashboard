const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');

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
            `SELECT uc.*, d.name AS device_name, d.serial
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

/* POST add credential to user */
router.post('/:id/credentials', async (req, res) => {
    const { device_id, type, identifier } = req.body;
    if (!device_id || !type || !identifier)
        return res.status(400).json({ error: 'device_id, type, identifier required' });
    if (!['rfid', 'pin', 'qr'].includes(type))
        return res.status(400).json({ error: 'type must be rfid, pin, or qr' });

    try {
        const result = await pool.query(
            `INSERT INTO user_credentials (user_id, device_id, type, identifier)
             VALUES ($1, $2, $3, $4) RETURNING *`,
            [req.params.id, device_id, type, identifier.trim()]
        );
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505')
            return res.status(409).json({ error: 'This credential is already assigned on this device' });
        res.status(500).json({ error: err.message });
    }
});

/* DELETE credential */
router.delete('/credentials/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM user_credentials WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;