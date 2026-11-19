const express = require('express');
const router  = express.Router();
const pool    = require('../db/pool');
const { requirePerm } = require('../auth');

/* Read the audit trail.
   - super_admin: everything (optional ?org_id= filter)
   - org_admin:   only entries of their own customer
   Query: ?limit=50 (max 200) &offset=0 &action=device.command &org_id= */
router.get('/', requirePerm('audit.view'), async (req, res) => {
    try {
        const limit  = Math.min(Math.max(parseInt(req.query.limit, 10)  || 50, 1), 200);
        const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

        const where = [], params = [];
        if (req.user.role === 'super_admin') {
            if (req.query.org_id) { params.push(parseInt(req.query.org_id, 10)); where.push(`a.org_id = $${params.length}`); }
        } else {
            params.push(req.user.orgId); where.push(`a.org_id = $${params.length}`);
        }
        if (req.query.action) { params.push(String(req.query.action)); where.push(`a.action = $${params.length}`); }

        params.push(limit, offset);
        const result = await pool.query(
            `SELECT a.id, a.created_at, a.username, a.org_id, o.name AS org_name,
                    a.action, a.target_type, a.target_id, a.details, a.ip
               FROM audit_log a
               LEFT JOIN organizations o ON o.id = a.org_id
              ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
              ORDER BY a.created_at DESC, a.id DESC
              LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
