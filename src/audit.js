/* ============================================================
   Audit trail helper.
   Never throws and never blocks the request: a failure to write
   the audit row must not break the action the user asked for.
   Do NOT put secrets (passwords, PINs, credential data, Wi-Fi
   passwords) in `details`.
   ============================================================ */
const pool = require('./db/pool');

async function audit(req, action, opts = {}) {
    const { targetType = null, targetId = null, orgId, details = null } = opts;
    try {
        const u = (req && req.user) || {};
        await pool.query(
            `INSERT INTO audit_log (user_id, username, org_id, action, target_type, target_id, details, ip)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
                u.id        ?? null,
                u.username  ?? (opts.username ?? null),
                orgId !== undefined ? orgId : (u.orgId ?? null),
                action,
                targetType,
                targetId !== null && targetId !== undefined ? String(targetId) : null,
                details ? JSON.stringify(details) : null,
                req && req.ip ? String(req.ip).slice(0, 64) : null
            ]
        );
    } catch (err) {
        console.error('audit write failed:', err.message);
    }
}

module.exports = { audit };
