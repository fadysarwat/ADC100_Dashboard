const express      = require('express');
const path         = require('path');
const http         = require('http');
const session      = require('express-session');
require('dotenv').config();

const initDb            = require('./src/db/init');
const pool              = require('./src/db/pool');
const { requireAuth }   = require('./src/auth');
const { createHub }     = require('./src/ws');
const authRouter        = require('./src/routes/auth');
const devicesRouter     = require('./src/routes/devices');
const credentialsRouter = require('./src/routes/credentials');
const tempPinsRouter    = require('./src/routes/temppins');
const appRouter         = require('./src/routes/app');
const appUsersRouter    = require('./src/routes/appusers');
const doorUsersRouter   = require('./src/routes/users');
const orgsRouter        = require('./src/routes/orgs');
const dashUsersRouter   = require('./src/routes/dashusers');
const auditRouter       = require('./src/routes/audit');
const { startMqtt }     = require('./src/mqtt');
const startMonitor      = require('./src/monitor');

const app    = express();
app.disable('x-powered-by');
const server = http.createServer(app);
const hub    = createHub();          /* authenticated, tenant-filtered WebSocket (src/ws.js) */
app.locals.hub = hub;
const PORT   = process.env.PORT || 3000;

/* Basic security headers on every response. (No Content-Security-Policy yet:
   the pages use inline scripts; moving them out is a separate change.) */
app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('X-Frame-Options', 'DENY');
    res.set('Referrer-Policy', 'same-origin');
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (process.env.NODE_ENV === 'production')
        res.set('Strict-Transport-Security', 'max-age=15552000');
    next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const PROD = process.env.NODE_ENV === 'production';
if (PROD && !process.env.SESSION_SECRET) {
    console.error('FATAL: SESSION_SECRET must be set in production.');
    process.exit(1);
}
if (PROD) app.set('trust proxy', 1);     /* behind Railway's proxy: needed for secure cookies */

/* Sessions live in PostgreSQL (table "session", created on first use), so
   logins survive deploys/restarts and work with more than one server. */
const PgStore = require('connect-pg-simple')(session);
const sessionMiddleware = session({
    store:             new PgStore({ pool, tableName: 'session', createTableIfMissing: true }),
    secret:            process.env.SESSION_SECRET || 'dev-only-secret-not-for-production',
    resave:            false,
    saveUninitialized: false,
    cookie:            { maxAge: 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'lax', secure: PROD }
});
app.use(sessionMiddleware);
hub.attach(server, sessionMiddleware);

/* ── Auth: login / logout / me / change-password (src/routes/auth.js) ── */
app.use('/api', authRouter);

/* ── Protect API routes ── */
app.use('/api/devices',     requireAuth, devicesRouter);
app.use('/api/credentials', requireAuth, credentialsRouter);
app.use('/api/temppins',    requireAuth, tempPinsRouter);
app.use('/api/app',         appRouter);
app.use('/api/appusers',    requireAuth, appUsersRouter);
app.use('/api/users',       requireAuth, doorUsersRouter);
app.use('/api/orgs',            requireAuth, orgsRouter);
app.use('/api/dashboard-users', requireAuth, dashUsersRouter);
app.use('/api/audit',           requireAuth, auditRouter);

/* ── Protect HTML pages ──
   Every page needs a logged-in user AND the permission that page is for.
   A logged-in user without the permission is sent back to the dashboard
   (the page's data is protected by the API anyway; this keeps the UI tidy).
   Pages not listed here (login.html, js/…) are public static files. */
const { hasPerm } = require('./src/auth');
const PAGES = {
    '/':             { file: 'index.html',    any: ['device.view'] },
    '/index.html':   { file: 'index.html',    any: ['device.view'] },
    '/device.html':  { file: 'device.html',   any: ['device.view'] },
    '/serials.html': { file: 'serials.html',  any: ['serials.manage'] },
    '/tempqr.html':  { file: 'tempqr.html',   any: ['qr.global'] },
    '/temppin.html': { file: 'temppin.html',  any: ['temppin.manage'] },
    '/appusers.html':{ file: 'appusers.html', any: ['appusers.manage'] },
    '/users.html':   { file: 'users.html',    any: ['doorusers.manage'] },
    '/admin.html':   { file: 'admin.html',    any: ['orgs.manage', 'users.manage', 'audit.view'] }
};
Object.entries(PAGES).forEach(([route, page]) => {
    app.get(route, requireAuth, (req, res) => {
        if (!page.any.some(p => hasPerm(req.user.role, p))) {
            return res.redirect(route === '/' ? '/login.html' : '/');
        }
        res.sendFile(path.join(__dirname, 'public', page.file));
    });
});

/* ── Public files (login page) ── */
app.use(express.static(path.join(__dirname, 'public')));

async function start() {
    await initDb();
    startMqtt(hub.broadcast);
    startMonitor(hub.broadcast);
    server.listen(PORT, () => {
        console.log(`ADC-100 Dashboard running on http://localhost:${PORT}`);
    });
}

/* Started only when run directly (`node server.js`); tests import the app instead. */
if (require.main === module) start();

module.exports = { app, server, hub };
