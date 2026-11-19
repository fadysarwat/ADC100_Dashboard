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
const server = http.createServer(app);
const hub    = createHub();          /* authenticated, tenant-filtered WebSocket (src/ws.js) */
app.locals.hub = hub;
const PORT   = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const sessionMiddleware = session({
    secret:            process.env.SESSION_SECRET,
    resave:            false,
    saveUninitialized: false,
    cookie:            { maxAge: 24 * 60 * 60 * 1000 }
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

/* ── Protect HTML pages ── */
app.get('/', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/index.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/device.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'device.html'));
});
app.get('/serials.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'serials.html'));
});
app.get('/tempqr.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'tempqr.html'));
});
app.get('/temppin.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'temppin.html'));
});
app.get('/appusers.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'appusers.html'));
});
app.get('/users.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'users.html'));
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
