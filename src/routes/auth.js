const express = require('express');
const bcrypt  = require('bcrypt');
const router  = express.Router();
const pool    = require('../db/pool');
const { requireAuth, permsForRole } = require('../auth');
const { createLoginLimiter } = require('../ratelimit');
const limiter = createLoginLimiter();
router.limiter = limiter;

/* POST /api/login */
router.post('/login', limiter.guard, async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password)
        return res.status(400).json({ error: 'Username and password required' });

    try {
        const result = await pool.query(
            `SELECT u.*, o.is_active AS org_active
               FROM users u
               LEFT JOIN organizations o ON o.id = u.org_id
              WHERE u.username = $1`,
            [username]
        );
        const user = result.rows[0];

        /* Same answer for unknown user, wrong password, disabled user and
           disabled customer: do not reveal which one it was. */
        const invalid = () => { limiter.fail(req, username); return res.status(401).json({ error: 'Invalid credentials' }); };

        if (!user) return invalid();
        const match = await bcrypt.compare(password, user.password);
        if (!match) return invalid();
        if (!user.is_active) return invalid();
        if (user.org_id !== null && !user.org_active) return invalid();

        limiter.ok(req, username);

        /* New session id on login (prevents session fixation). */
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: 'Session error' });
            req.session.userId = user.id;
            req.session.save((err2) => {
                if (err2) return res.status(500).json({ error: 'Session error' });
                res.json({ success: true, role: user.role });
            });
        });
    } catch (err) {
        console.error('login error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

/* GET /api/logout */
router.get('/logout', (req, res) => {
    const sid = req.sessionID;
    req.session.destroy(() => {
        if (req.app.locals.hub) req.app.locals.hub.disconnectSession(sid);
        res.redirect('/login.html');
    });
});

/* GET /api/me — who am I, what may I do (used by the UI to hide controls;
   the server enforces the same rules independently). */
router.get('/me', requireAuth, (req, res) => {
    const u = req.user;
    res.json({
        id:          u.id,
        username:    u.username,
        fullName:    u.fullName,
        role:        u.role,
        orgId:       u.orgId,
        orgName:     u.orgName,
        permissions: permsForRole(u.role)
    });
});

/* POST /api/change-password */
router.post('/change-password', requireAuth, async (req, res) => {
    const { current_password, new_password } = req.body || {};
    if (!current_password || !new_password)
        return res.status(400).json({ error: 'Both fields required' });
    if (new_password.length < 6)
        return res.status(400).json({ error: 'Password must be at least 6 characters' });

    try {
        const result = await pool.query('SELECT password FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'User not found' });

        const match = await bcrypt.compare(current_password, result.rows[0].password);
        if (!match)
            return res.status(401).json({ error: 'Current password is incorrect' });

        const hash = await bcrypt.hash(new_password, 10);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, req.user.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
