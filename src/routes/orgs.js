const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requirePerm } = require('../auth');
const { audit } = require('../audit');

/* Customers (organizations). Platform-only: only super_admin holds 'orgs.manage'. */
router.use(requirePerm('orgs.manage'));

/* GET all customers with counters */
router.get('/', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT o.*,
                    (SELECT COUNT(*) FROM devices d WHERE d.org_id = o.id)::int AS device_count,
                    (SELECT COUNT(*) FROM users   u WHERE u.org_id = o.id)::int AS user_count
               FROM organizations o
              ORDER BY o.name ASC`
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* POST create customer */
router.post('/', async (req, res) => {
    const name = (req.body.name || '').trim();
    if (name.length < 2 || name.length > 128)
        return res.status(400).json({ error: 'name must be 2–128 characters' });
    try {
        const result = await pool.query(
            'INSERT INTO organizations (name) VALUES ($1) RETURNING *',
            [name]
        );
        await audit(req, 'org.create', { targetType: 'org', targetId: result.rows[0].id, orgId: result.rows[0].id, details: { name } });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505')
            return res.status(409).json({ error: 'A customer with this name already exists' });
        res.status(500).json({ error: err.message });
    }
});

/* PATCH rename / enable / disable customer */
router.patch('/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(404).json({ error: 'Customer not found' });

    const fields = [];
    const params = [];
    if (req.body.name !== undefined) {
        const name = String(req.body.name).trim();
        if (name.length < 2 || name.length > 128)
            return res.status(400).json({ error: 'name must be 2–128 characters' });
        params.push(name); fields.push(`name = $${params.length}`);
    }
    if (req.body.is_active !== undefined) {
        params.push(!!req.body.is_active); fields.push(`is_active = $${params.length}`);
    }
    if (fields.length === 0) return res.status(400).json({ error: 'nothing to update' });

    try {
        params.push(id);
        const result = await pool.query(
            `UPDATE organizations SET ${fields.join(', ')} WHERE id = $${params.length} RETURNING *`,
            params
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Customer not found' });

        /* Disabling a customer logs all of its users out of live connections now. */
        if (req.body.is_active !== undefined && !result.rows[0].is_active && req.app.locals.hub)
            req.app.locals.hub.disconnectOrg(id);

        await audit(req, 'org.update', { targetType: 'org', targetId: id, orgId: id, details: req.body });
        res.json(result.rows[0]);
    } catch (err) {
        if (err.code === '23505')
            return res.status(409).json({ error: 'A customer with this name already exists' });
        res.status(500).json({ error: err.message });
    }
});

/* DELETE customer — only when it owns nothing */
router.delete('/:id', async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(404).json({ error: 'Customer not found' });
    try {
        const org = await pool.query('SELECT * FROM organizations WHERE id = $1', [id]);
        if (org.rows.length === 0) return res.status(404).json({ error: 'Customer not found' });

        const devs = await pool.query('SELECT COUNT(*)::int AS n FROM devices WHERE org_id = $1', [id]);
        if (devs.rows[0].n > 0)
            return res.status(409).json({ error: 'This customer still owns devices. Move or delete them first.' });

        await pool.query('DELETE FROM organizations WHERE id = $1', [id]);   /* its dashboard users cascade */
        if (req.app.locals.hub) req.app.locals.hub.disconnectOrg(id);
        await audit(req, 'org.delete', { targetType: 'org', targetId: id, orgId: null, details: { name: org.rows[0].name } });
        res.json({ success: true });
    } catch (err) {
        if (err.code === '23503')
            return res.status(409).json({ error: 'This customer still has door users or app users. Remove them first.' });
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
