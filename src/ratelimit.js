/* Login rate limiting (no extra dependency, in memory: one server instance).
 *
 * Two counters per login route:
 *   - per IP + username : MAX_USER failed attempts per window
 *   - per IP            : MAX_IP failed attempts per window (many usernames from one address)
 * Only FAILED attempts count; a successful login clears the per-user counter.
 * When a limit is reached the answer is 429 + Retry-After until the window ends,
 * even if the next password is correct (otherwise an attacker keeps guessing).
 */
const WINDOW_MS = 15 * 60 * 1000;
const MAX_USER  = 5;
const MAX_IP    = 30;

function createLoginLimiter(opts = {}) {
    const windowMs = opts.windowMs || WINDOW_MS;
    const maxUser  = opts.maxUser  || MAX_USER;
    const maxIp    = opts.maxIp    || MAX_IP;
    const hits = new Map();                       /* key -> { count, resetAt } */

    function bump(key) {
        const now = Date.now();
        let e = hits.get(key);
        if (!e || e.resetAt <= now) { e = { count: 0, resetAt: now + windowMs }; hits.set(key, e); }
        e.count++;
        return e;
    }
    function peek(key) {
        const e = hits.get(key);
        return (e && e.resetAt > Date.now()) ? e : null;
    }
    const keyUser = (req, username) => 'u|' + (req.ip || '') + '|' + String(username || '').toLowerCase().slice(0, 100);
    const keyIp   = (req) => 'i|' + (req.ip || '');

    /* Express middleware: refuse early when blocked. */
    function guard(req, res, next) {
        const u = peek(keyUser(req, req.body && req.body.username));
        const i = peek(keyIp(req));
        const blocked = (u && u.count >= maxUser) ? u : (i && i.count >= maxIp) ? i : null;
        if (blocked) {
            const secs = Math.max(1, Math.ceil((blocked.resetAt - Date.now()) / 1000));
            res.set('Retry-After', String(secs));
            return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
        }
        next();
    }
    function fail(req, username) { bump(keyUser(req, username)); bump(keyIp(req)); }
    function ok(req, username)   { hits.delete(keyUser(req, username)); }
    function reset()             { hits.clear(); }

    /* Forget expired entries so the map cannot grow without limit. */
    const t = setInterval(() => {
        const now = Date.now();
        for (const [k, e] of hits) if (e.resetAt <= now) hits.delete(k);
    }, 60 * 1000);
    if (t.unref) t.unref();

    return { guard, fail, ok, reset };
}

module.exports = { createLoginLimiter };
