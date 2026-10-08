const express      = require('express');
const path         = require('path');
const http         = require('http');
const WebSocket    = require('ws');
const session      = require('express-session');
const bcrypt       = require('bcrypt');
require('dotenv').config();

const initDb            = require('./src/db/init');
const pool              = require('./src/db/pool');
const devicesRouter     = require('./src/routes/devices');
const credentialsRouter = require('./src/routes/credentials');
const tempPinsRouter    = require('./src/routes/temppins');
const appRouter         = require('./src/routes/app');
const appUsersRouter    = require('./src/routes/appusers');
const { startMqtt }     = require('./src/mqtt');
const startMonitor      = require('./src/monitor');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });
const PORT   = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret:            process.env.SESSION_SECRET,
    resave:            false,
    saveUninitialized: false,
    cookie:            { maxAge: 24 * 60 * 60 * 1000 }
}));

/* ── Auth middleware ── */
function requireAuth(req, res, next) {
    if (req.session && req.session.loggedIn) return next();
    if (req.path.startsWith('/api/') || req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.redirect('/login.html');
}

/* ── Login endpoint ── */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        if (result.rows.length === 0)
            return res.status(401).json({ error: 'Invalid credentials' });

        const user  = result.rows[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match)
            return res.status(401).json({ error: 'Invalid credentials' });

        req.session.loggedIn = true;
        req.session.username = user.username;
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ── Logout endpoint ── */
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

/* ── Change password endpoint ── */
app.post('/api/change-password', requireAuth, async (req, res) => {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password)
        return res.status(400).json({ error: 'Both fields required' });
    if (new_password.length < 6)
        return res.status(400).json({ error: 'Password must be at least 6 characters' });

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [req.session.username]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'User not found' });

        const user  = result.rows[0];
        const match = await bcrypt.compare(current_password, user.password);
        if (!match)
            return res.status(401).json({ error: 'Current password is incorrect' });

        const hash = await bcrypt.hash(new_password, 10);
        await pool.query(
            'UPDATE users SET password = $1 WHERE username = $2',
            [hash, req.session.username]
        );

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* ── Protect API routes ── */
app.use('/api/devices',     requireAuth, devicesRouter);
app.use('/api/credentials', requireAuth, credentialsRouter);
app.use('/api/temppins',    requireAuth, tempPinsRouter);
app.use('/api/app',         appRouter);
app.use('/api/appusers',    requireAuth, appUsersRouter);

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

/* ── Public files (login page) ── */
app.use(express.static(path.join(__dirname, 'public')));

/* Broadcast to all connected WebSocket clients */
function broadcast(data) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
}

wss.on('connection', (ws) => {
    console.log('Dashboard client connected');
    ws.on('close', () => console.log('Dashboard client disconnected'));
});

async function start() {
    await initDb();
    startMqtt(broadcast);
    startMonitor(broadcast);
    server.listen(PORT, () => {
        console.log(`ADC-100 Dashboard running on http://localhost:${PORT}`);
    });
}

start();