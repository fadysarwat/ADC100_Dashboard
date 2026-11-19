/* ============================================================
   RBAC / multi-tenant integration test.

   Runs the REAL application (server.js wiring, routes, middleware,
   WebSocket hub) against a DISPOSABLE PostgreSQL database. MQTT is
   stubbed: nothing is ever sent to the broker or to a device.

   Usage:
     TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/adc_test \
       node tests/rbac.integration.js

   SAFETY: the target database is wiped (DROP SCHEMA public CASCADE).
   The script refuses to run unless the database name contains "test".
   ============================================================ */
const path = require('path');
const ROOT = path.join(__dirname, '..');

const TEST_URL = process.env.TEST_DATABASE_URL;
if (!TEST_URL) {
    console.error('Set TEST_DATABASE_URL to a disposable database (its name must contain "test").');
    process.exit(2);
}
let dbName = '';
try { dbName = new URL(TEST_URL).pathname.replace(/^\//, ''); } catch (_) { /* fall through */ }
if (!/test/i.test(dbName)) {
    console.error(`Refusing to run: database name "${dbName}" does not contain "test". This script wipes the database.`);
    process.exit(2);
}

/* Must be set BEFORE any application module is loaded (dotenv never overrides). */
process.env.DATABASE_URL     = TEST_URL;
process.env.NODE_ENV         = 'test';
process.env.SESSION_SECRET   = 'test-session-secret';
process.env.MQTT_SECRET      = 'test-mqtt-secret';
process.env.DEVICE_MASTER_KEY = 'test-master-key-0123456789abcdef-0123456789';
process.env.WS_REVALIDATE_MS = '400';

const bcrypt    = require('bcrypt');
const WebSocket = require('ws');
const pool      = require(path.join(ROOT, 'src/db/pool'));
const initDb    = require(path.join(ROOT, 'src/db/init'));
const fs        = require('fs');

/* Stub MQTT before the routes load (they destructure `publish` at require time). */
const mqttModule = require(path.join(ROOT, 'src/mqtt'));
const published  = [];
mqttModule.publish = (topic, message) => published.push({ topic, msg: JSON.parse(message) });

const { server, hub } = require(path.join(ROOT, 'server.js'));

/* ── tiny test harness ── */
let pass = 0, fail = 0;
const failures = [];
function section(t) { console.log(`\n# ${t}`); }
function check(name, cond, extra = '') {
    if (cond) { pass++; console.log('  ok    ' + name); }
    else      { fail++; failures.push(name); console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

let base;
async function call(cookie, method, url, body) {
    const r = await fetch(base + url, {
        method,
        redirect: 'manual',
        headers: { ...(cookie ? { cookie } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
        body: body ? JSON.stringify(body) : undefined
    });
    let json = null, text = '';
    try { text = await r.text(); json = JSON.parse(text); } catch (_) { /* not json */ }
    return { status: r.status, body: json, text, headers: r.headers };
}
async function login(username, password = 'pw123456') {
    const r = await fetch(base + '/api/login', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    return { status: r.status, cookie: (r.headers.get('set-cookie') || '').split(';')[0] };
}
const serials = r => Array.isArray(r.body) ? r.body.map(x => x.serial).sort().join(',') : '(not a list)';

/* ── WebSocket client helper ── */
function wsConnect(cookie, origin) {
    return new Promise((resolve) => {
        const headers = {};
        if (cookie) headers.cookie = cookie;
        if (origin) headers.origin = origin;
        const ws = new WebSocket(`ws://127.0.0.1:${server.address().port}`, { headers });
        const c = { ws, msgs: [], closedCode: null, status: null };
        ws.on('message', m => c.msgs.push(JSON.parse(m.toString())));
        ws.on('close', code => { c.closedCode = code; });
        ws.on('unexpected-response', (req, res) => { c.status = res.statusCode; resolve(c); });
        ws.on('error', () => {});
        ws.on('open', () => { c.status = 101; resolve(c); });
    });
}
const got = (c, type, deviceId) => c.msgs.some(m => m.type === type && m.deviceId === deviceId);

(async () => {
    /* ============ database setup (disposable) ============ */
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    await pool.query(fs.readFileSync(path.join(ROOT, 'src/db/schema.sql'), 'utf8'));
    /* Objects that exist on the live database but are not in schema.sql (created by hand). */
    await pool.query(`
        ALTER TABLE devices ADD COLUMN IF NOT EXISTS relay_mode VARCHAR(16) DEFAULT 'timed';
        ALTER TABLE devices ADD COLUMN IF NOT EXISTS relay_duration INTEGER;
        ALTER TABLE devices ADD COLUMN IF NOT EXISTS ble_name VARCHAR(64);
        ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS door_user_id INTEGER;
        CREATE TABLE IF NOT EXISTS door_users (
            id SERIAL PRIMARY KEY, name VARCHAR(128) NOT NULL, active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW());
        CREATE TABLE IF NOT EXISTS user_credentials (
            id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES door_users(id) ON DELETE CASCADE,
            device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE, type VARCHAR(8),
            identifier VARCHAR(128), cred_data VARCHAR(128), created_at TIMESTAMP DEFAULT NOW(),
            UNIQUE (device_id, type, cred_data));
    `);
    await initDb();

    const hash = await bcrypt.hash('pw123456', 4);
    const q = (sql, p) => pool.query(sql, p);
    const one = async (sql, p) => (await q(sql, p)).rows[0];

    const A  = (await one("INSERT INTO organizations(name) VALUES('Customer A') RETURNING id")).id;
    const B  = (await one("INSERT INTO organizations(name) VALUES('Customer B') RETURNING id")).id;
    const mkUser = async (u, role, org, extra = {}) =>
        (await one('INSERT INTO users(username,password,role,org_id,is_active) VALUES($1,$2,$3,$4,$5) RETURNING id',
            [u, hash, role, org, extra.active ?? true])).id;

    const idSuper = await mkUser('super',   'super_admin', null);
    const idAA    = await mkUser('a_admin', 'org_admin',   A);
    const idAO    = await mkUser('a_op',    'operator',    A);
    const idAO2   = await mkUser('a_op2',   'operator',    A);
    const idAV    = await mkUser('a_view',  'viewer',      A);
    const idBA    = await mkUser('b_admin', 'org_admin',   B);
    await mkUser('disabled', 'org_admin', A, { active: false });

    const mkDev = async (s, org) => (await one(
        'INSERT INTO devices(serial,mqtt_id,name,org_id) VALUES($1,$1,$1,$2) RETURNING id', [s, org])).id;
    const d1 = await mkDev('D1', A), d2 = await mkDev('D2', A), d3 = await mkDev('D3', B), d4 = await mkDev('D4', null);

    /* a_op2 is restricted to D1 only */
    await q('INSERT INTO dashboard_user_device_access(user_id,device_id) VALUES($1,$2)', [idAO2, d1]);
    await q('UPDATE users SET device_restricted = TRUE WHERE id = $1', [idAO2]);

    /* seed data of both customers */
    const credA = (await one("INSERT INTO credentials(device_id,label,cred_type,cred_data) VALUES($1,'keyA','pin','1111') RETURNING id", [d1])).id;
    const credB = (await one("INSERT INTO credentials(device_id,label,cred_type,cred_data) VALUES($1,'keyB','pin','2222') RETURNING id", [d3])).id;
    const pinA  = (await one("INSERT INTO temp_pins(device_id,pin,label,iat,exp) VALUES($1,'1234','tA',NOW(),NOW()+interval '1 day') RETURNING id", [d1])).id;
    const pinB  = (await one("INSERT INTO temp_pins(device_id,pin,label,iat,exp) VALUES($1,'5678','tB',NOW(),NOW()+interval '1 day') RETURNING id", [d3])).id;
    await q("INSERT INTO access_logs(device_id,method,result) VALUES($1,'RFID','GRANTED'),($2,'PIN','DENIED')", [d1, d3]);
    await q("INSERT INTO heartbeats(device_id,fw,uptime) VALUES($1,'1.1.0',5),($2,'1.1.0',6)", [d1, d3]);
    const duA = (await one("INSERT INTO door_users(name,org_id) VALUES('Alice (A)',$1) RETURNING id", [A])).id;
    const duB = (await one("INSERT INTO door_users(name,org_id) VALUES('Bob (B)',$1) RETURNING id", [B])).id;
    const ucB = (await one("INSERT INTO user_credentials(user_id,device_id,type,identifier,cred_data) VALUES($1,$2,'rfid','Bob (B)','BOBUID') RETURNING id", [duB, d3])).id;
    const auA = (await one("INSERT INTO app_users(username,password,full_name,org_id) VALUES('app_a',$1,'App A',$2) RETURNING id", [hash, A])).id;
    const auB = (await one("INSERT INTO app_users(username,password,full_name,org_id) VALUES('app_b',$1,'App B',$2) RETURNING id", [hash, B])).id;
    await q('INSERT INTO user_door_access(user_id,device_id) VALUES($1,$2)', [auB, d3]);

    await new Promise(r => server.listen(0, r));
    base = `http://127.0.0.1:${server.address().port}`;

    const S  = await login('super'),   AA = await login('a_admin'), AO = await login('a_op');
    const AO2 = await login('a_op2'),  AV = await login('a_view'),  BA = await login('b_admin');

    /* ============ 1. pages & login ============ */
    section('1. pages require login; login rules');
    check('anonymous /device.html redirects to login', (await call(null, 'GET', '/device.html')).status === 302);
    check('anonymous API -> 401', (await call(null, 'GET', '/api/devices')).status === 401);
    check('wrong password -> 401', (await login('super', 'nope')).status === 401);
    check('unknown user -> 401', (await login('ghost')).status === 401);
    check('disabled user -> 401', (await login('disabled')).status === 401);
    check('all valid logins succeed', [S, AA, AO, AO2, AV, BA].every(x => x.status === 200 && x.cookie));
    const me = await call(AV.cookie, 'GET', '/api/me');
    check('/api/me returns role, customer and permissions', me.body.role === 'viewer' && me.body.orgName === 'Customer A' && !me.body.permissions.includes('device.command'));

    /* ============ 2. device list is tenant-scoped ============ */
    section('2. each customer sees only its own devices');
    check('super sees all 4', serials(await call(S.cookie, 'GET', '/api/devices')) === 'D1,D2,D3,D4');
    check('A admin sees D1,D2', serials(await call(AA.cookie, 'GET', '/api/devices')) === 'D1,D2');
    check('A operator sees D1,D2', serials(await call(AO.cookie, 'GET', '/api/devices')) === 'D1,D2');
    check('A restricted operator sees D1 only', serials(await call(AO2.cookie, 'GET', '/api/devices')) === 'D1');
    check('A viewer sees D1,D2', serials(await call(AV.cookie, 'GET', '/api/devices')) === 'D1,D2');
    check('B admin sees D3 only', serials(await call(BA.cookie, 'GET', '/api/devices')) === 'D3');

    /* ============ 3. device routes ============ */
    section('3. device routes: cross-customer access is hidden (404), roles are enforced (403)');
    for (const [label, url] of [['heartbeats', `/${d3}/heartbeats`], ['logs', `/${d3}/logs`], ['logs/export', `/${d3}/logs/export`]])
        check(`A admin GET ${label} of B device -> 404`, (await call(AA.cookie, 'GET', '/api/devices' + url)).status === 404);
    check('A admin GET own logs -> 200', (await call(AA.cookie, 'GET', `/api/devices/${d1}/logs`)).status === 200);
    check('A viewer GET own logs -> 200', (await call(AV.cookie, 'GET', `/api/devices/${d1}/logs`)).status === 200);
    check('A viewer cannot export logs -> 403', (await call(AV.cookie, 'GET', `/api/devices/${d1}/logs/export`)).status === 403);
    check('A restricted operator -> D2 logs 404', (await call(AO2.cookie, 'GET', `/api/devices/${d2}/logs`)).status === 404);
    check('A admin PATCH notes own -> 200', (await call(AA.cookie, 'PATCH', `/api/devices/${d1}/notes`, { notes: 'x' })).status === 200);
    check('A admin PATCH notes of B device -> 404', (await call(AA.cookie, 'PATCH', `/api/devices/${d3}/notes`, { notes: 'x' })).status === 404);
    check('A operator PATCH notes -> 403', (await call(AO.cookie, 'PATCH', `/api/devices/${d1}/notes`, { notes: 'x' })).status === 403);
    check('A admin PATCH relay own -> 200', (await call(AA.cookie, 'PATCH', `/api/devices/${d1}/relay`, { relay_mode: 'timed', relay_duration: 5 })).status === 200);
    check('A admin cannot DELETE device -> 403', (await call(AA.cookie, 'DELETE', `/api/devices/${d1}`)).status === 403);
    check('A admin cannot ACTIVATE device -> 403', (await call(AA.cookie, 'POST', `/api/devices/${d1}/activate`)).status === 403);
    check('A admin cannot create serial -> 403', (await call(AA.cookie, 'POST', '/api/devices/generate-serial')).status === 403);
    check('A admin cannot list serials -> 403', (await call(AA.cookie, 'GET', '/api/devices/serials')).status === 403);
    check('A admin cannot create device -> 403', (await call(AA.cookie, 'POST', '/api/devices', { serial: 'X' })).status === 403);
    check('A admin cannot make global temp-QR -> 403', (await call(AA.cookie, 'POST', '/api/devices/temp-qr', { iat: '2030-01-01', exp: '2030-01-02' })).status === 403);
    check('super can make temp-QR', (await call(S.cookie, 'POST', '/api/devices/temp-qr', { iat: '2030-01-01', exp: '2030-01-02' })).status === 200);

    section('3b. device commands');
    const cmd = (c, serial, cmdName, extra = {}) => call(c, 'POST', '/api/devices/command', { serial, cmd: cmdName, ts: 1700000000, ...extra });
    published.length = 0;
    check('A operator opens own door -> 200', (await cmd(AO.cookie, 'D1', 'open')).status === 200);
    check('...and exactly one MQTT message went to D1', published.length === 1 && published[0].topic === 'adc100/D1/cmd' && published[0].msg.cmd === 'open');
    published.length = 0;
    check('A operator opens B door -> 404', (await cmd(AO.cookie, 'D3', 'open')).status === 404);
    check('A admin opens B door -> 404', (await cmd(AA.cookie, 'D3', 'open')).status === 404);
    check('A admin opens unassigned door -> 404', (await cmd(AA.cookie, 'D4', 'open')).status === 404);
    check('NOTHING was published for those refused commands', published.length === 0);
    check('A restricted operator opens D2 -> 404', (await cmd(AO2.cookie, 'D2', 'open')).status === 404);
    check('A viewer cannot open -> 403', (await cmd(AV.cookie, 'D1', 'open')).status === 403);
    check('A viewer may request logs -> 200', (await cmd(AV.cookie, 'D1', 'get_logs')).status === 200);
    check('A operator cannot clear logs -> 403', (await cmd(AO.cookie, 'D1', 'clear_logs')).status === 403);
    check('A admin can clear logs -> 200', (await cmd(AA.cookie, 'D1', 'clear_logs')).status === 200);
    check('A viewer may request status -> 200', (await cmd(AV.cookie, 'D1', 'get_status')).status === 200);
    check('A operator cannot restart -> 403', (await cmd(AO.cookie, 'D1', 'restart')).status === 403);
    check('A operator cannot reset wifi -> 403', (await cmd(AO.cookie, 'D1', 'reset_wifi')).status === 403);
    check('A admin can restart -> 200', (await cmd(AA.cookie, 'D1', 'restart')).status === 200);
    check('A admin restart on B door -> 404', (await cmd(AA.cookie, 'D3', 'restart')).status === 404);
    check('A admin cannot run OTA -> 403', (await cmd(AA.cookie, 'D1', 'ota_update', { url: 'http://x/fw.bin' })).status === 403);
    check('A admin unknown command -> 403 (deny by default)', (await cmd(AA.cookie, 'D1', 'format_everything')).status === 403);
    published.length = 0;
    check('super can run OTA on any customer', (await cmd(S.cookie, 'D3', 'ota_update', { url: 'http://x/fw.bin' })).status === 200 && published.length === 1);
    check('A admin sets wifi on own door -> 200', (await cmd(AA.cookie, 'D1', 'set_wifi', { ssid: 'office', password: 'wifi-secret-xyz' })).status === 200);

    /* ============ 4. credentials & temp PINs ============ */
    section('4. credentials and temporary PINs');
    const rawView = await call(AO.cookie, 'GET', `/api/credentials/${d1}`);
    check('operator sees credential labels but NOT the secret', rawView.status === 200 && rawView.body.length >= 1 && rawView.body.every(r => r.cred_data === '••••'));
    const adminView = await call(AA.cookie, 'GET', `/api/credentials/${d1}`);
    check('org admin sees the secrets', adminView.body.some(r => r.cred_data === '1111'));
    check('viewer cannot read credentials -> 403', (await call(AV.cookie, 'GET', `/api/credentials/${d1}`)).status === 403);
    check('A admin reads B credentials -> 404', (await call(AA.cookie, 'GET', `/api/credentials/${d3}`)).status === 404);
    published.length = 0;
    check('operator cannot add credential -> 403', (await call(AO.cookie, 'POST', `/api/credentials/${d1}`, { label: 'n', cred_type: 'pin', cred_data: '9' })).status === 403);
    check('A admin adds credential on own door -> 200', (await call(AA.cookie, 'POST', `/api/credentials/${d1}`, { label: 'new', cred_type: 'pin', cred_data: 'SECRET-PIN-9876' })).status === 200);
    check('...and it was sent to D1 only', published.length === 1 && published[0].topic === 'adc100/D1/cmd');
    published.length = 0;
    const before = (await one('SELECT COUNT(*)::int n FROM credentials')).n;
    check('A admin adds credential on B door -> 404', (await call(AA.cookie, 'POST', `/api/credentials/${d3}`, { label: 'x', cred_type: 'pin', cred_data: '9' })).status === 404);
    check('...nothing saved and nothing published', (await one('SELECT COUNT(*)::int n FROM credentials')).n === before && published.length === 0);
    check('A admin deletes B credential via own device path -> 404', (await call(AA.cookie, 'DELETE', `/api/credentials/${d1}/${credB}`)).status === 404);
    check('A admin deletes B credential via B device path -> 404', (await call(AA.cookie, 'DELETE', `/api/credentials/${d3}/${credB}`)).status === 404);
    check('B credential still exists', !!(await one('SELECT id FROM credentials WHERE id = $1', [credB])));
    check('A admin deletes own credential -> 200', (await call(AA.cookie, 'DELETE', `/api/credentials/${d1}/${credA}`)).status === 200);

    check('viewer cannot read temp PINs -> 403', (await call(AV.cookie, 'GET', `/api/temppins/${d1}`)).status === 403);
    check('operator reads own temp PINs -> 200', (await call(AO.cookie, 'GET', `/api/temppins/${d1}`)).status === 200);
    check('A admin reads B temp PINs -> 404', (await call(AA.cookie, 'GET', `/api/temppins/${d3}`)).status === 404);
    check('operator creates temp PIN on own door -> 200', (await call(AO.cookie, 'POST', `/api/temppins/${d1}`, { iat: '2030-01-01', exp: '2030-01-02' })).status === 200);
    check('A admin creates temp PIN on B door -> 404', (await call(AA.cookie, 'POST', `/api/temppins/${d3}`, { iat: '2030-01-01', exp: '2030-01-02' })).status === 404);
    check('A admin deletes B temp PIN -> 404', (await call(AA.cookie, 'DELETE', `/api/temppins/${d3}/${pinB}`)).status === 404);
    check('B temp PIN still exists', !!(await one('SELECT id FROM temp_pins WHERE id = $1', [pinB])));
    check('A admin deletes own temp PIN -> 200', (await call(AA.cookie, 'DELETE', `/api/temppins/${d1}/${pinA}`)).status === 200);

    /* ============ 5. door users & mobile users ============ */
    section('5. door users (people at the door)');
    check('A admin lists only own door users', (await call(AA.cookie, 'GET', '/api/users')).body.map(u => u.name).join() === 'Alice (A)');
    check('operator cannot manage door users -> 403', (await call(AO.cookie, 'GET', '/api/users')).status === 403);
    check('viewer cannot manage door users -> 403', (await call(AV.cookie, 'GET', '/api/users')).status === 403);
    const created = await call(AA.cookie, 'POST', '/api/users', { name: 'Carol', org_id: B });
    check('A admin creates door user; customer is forced to A even if B is sent', created.status === 200 && created.body.org_id === A);
    check('A admin PATCH B door user -> 404', (await call(AA.cookie, 'PATCH', `/api/users/${duB}/active`, { active: false })).status === 404);
    check('A admin DELETE B door user -> 404', (await call(AA.cookie, 'DELETE', `/api/users/${duB}`)).status === 404);
    check('A admin reads B door user credentials -> 404', (await call(AA.cookie, 'GET', `/api/users/${duB}/credentials`)).status === 404);
    published.length = 0;
    check('A admin enrolls own user on own door -> 200', (await call(AA.cookie, 'POST', `/api/users/${duA}/credentials`, { device_id: d1, type: 'rfid', identifier: 'AABBCC' })).status === 200);
    check('...MQTT went to D1', published.length === 1 && published[0].topic === 'adc100/D1/cmd');
    published.length = 0;
    check('A admin enrolls own user on B door -> 404', (await call(AA.cookie, 'POST', `/api/users/${duA}/credentials`, { device_id: d3, type: 'rfid', identifier: 'ZZ' })).status === 404);
    check('A admin enrolls B user on own door -> 404', (await call(AA.cookie, 'POST', `/api/users/${duB}/credentials`, { device_id: d1, type: 'rfid', identifier: 'ZZ' })).status === 404);
    check('super cannot mix customers (A user on B door) -> 400', (await call(S.cookie, 'POST', `/api/users/${duA}/credentials`, { device_id: d3, type: 'rfid', identifier: 'ZZ' })).status === 400);
    check('nothing published for refused enrolments', published.length === 0);
    check('A admin deletes B user credential -> 404', (await call(AA.cookie, 'DELETE', `/api/users/credentials/${ucB}`)).status === 404);
    check('B user credential still exists', !!(await one('SELECT id FROM user_credentials WHERE id = $1', [ucB])));

    section('5b. mobile-app users');
    check('A admin lists only own app users', (await call(AA.cookie, 'GET', '/api/appusers')).body.map(u => u.username).join() === 'app_a');
    check('operator cannot manage app users -> 403', (await call(AO.cookie, 'GET', '/api/appusers')).status === 403);
    check('A admin grants own door to own app user -> 200', (await call(AA.cookie, 'POST', `/api/appusers/${auA}/doors`, { device_id: d1 })).status === 200);
    check('A admin grants B door to own app user -> 404', (await call(AA.cookie, 'POST', `/api/appusers/${auA}/doors`, { device_id: d3 })).status === 404);
    check('A admin grants own door to B app user -> 404', (await call(AA.cookie, 'POST', `/api/appusers/${auB}/doors`, { device_id: d1 })).status === 404);
    check('A admin toggles B app user -> 404', (await call(AA.cookie, 'PATCH', `/api/appusers/${auB}/toggle`)).status === 404);
    check('A admin deletes B app user -> 404', (await call(AA.cookie, 'DELETE', `/api/appusers/${auB}`)).status === 404);
    const newApp = await call(AA.cookie, 'POST', '/api/appusers', { username: 'app_new', password: 'secret123', org_id: B });
    check('A admin creates app user; customer forced to A', newApp.status === 200 && newApp.body.org_id === A);
    const mobile = await fetch(base + '/api/app/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'app_a', password: 'pw123456' }) });
    const mobileBody = await mobile.json();
    check('mobile login works and lists only its doors', mobile.status === 200 && mobileBody.doors.map(d => d.id).join() === String(d1));

    /* ============ 6. management: customers ============ */
    section('6. customers (platform only)');
    check('org admin cannot list customers -> 403', (await call(AA.cookie, 'GET', '/api/orgs')).status === 403);
    const orgs = await call(S.cookie, 'GET', '/api/orgs');
    check('super lists customers with counters', orgs.status === 200 && orgs.body.find(o => o.id === A).device_count === 2);
    const C = await call(S.cookie, 'POST', '/api/orgs', { name: 'Customer C' });
    check('super creates a customer', C.status === 200 && C.body.name === 'Customer C');
    check('duplicate customer name -> 409', (await call(S.cookie, 'POST', '/api/orgs', { name: 'Customer C' })).status === 409);
    check('too short name -> 400', (await call(S.cookie, 'POST', '/api/orgs', { name: 'x' })).status === 400);
    check('rename customer', (await call(S.cookie, 'PATCH', `/api/orgs/${C.body.id}`, { name: 'Customer C2' })).body.name === 'Customer C2');
    check('cannot delete a customer that owns devices -> 409', (await call(S.cookie, 'DELETE', `/api/orgs/${A}`)).status === 409);
    check('can delete an empty customer', (await call(S.cookie, 'DELETE', `/api/orgs/${C.body.id}`)).status === 200);

    /* ============ 7. management: dashboard users ============ */
    section('7. dashboard users');
    check('operator cannot manage users -> 403', (await call(AO.cookie, 'GET', '/api/dashboard-users')).status === 403);
    const aList = await call(AA.cookie, 'GET', '/api/dashboard-users');
    check('A admin lists only own customer, never a super admin', aList.status === 200 && aList.body.every(u => u.org_id === A && u.role !== 'super_admin'));
    check('A admin cannot create a super admin -> 403', (await call(AA.cookie, 'POST', '/api/dashboard-users', { username: 'evil', password: 'longpassword', role: 'super_admin' })).status === 403);
    const nv = await call(AA.cookie, 'POST', '/api/dashboard-users', { username: 'a_new_view', password: 'longpassword', role: 'viewer', org_id: B });
    check('A admin creates a user; customer forced to A even if B is sent', nv.status === 200 && nv.body.org_id === A && nv.body.role === 'viewer');
    check('weak password -> 400', (await call(AA.cookie, 'POST', '/api/dashboard-users', { username: 'weakpw', password: 'short', role: 'viewer' })).status === 400);
    check('bad username -> 400', (await call(AA.cookie, 'POST', '/api/dashboard-users', { username: 'a b', password: 'longpassword', role: 'viewer' })).status === 400);
    check('duplicate username -> 409', (await call(AA.cookie, 'POST', '/api/dashboard-users', { username: 'a_new_view', password: 'longpassword', role: 'viewer' })).status === 409);
    check('super must give a customer for a non-super role -> 400', (await call(S.cookie, 'POST', '/api/dashboard-users', { username: 'orphan', password: 'longpassword', role: 'viewer' })).status === 400);
    const sup2 = await call(S.cookie, 'POST', '/api/dashboard-users', { username: 'super2', password: 'longpassword', role: 'super_admin' });
    check('super creates another super admin (no customer)', sup2.status === 200 && sup2.body.org_id === null);
    check('A admin cannot see/modify a super admin -> 404', (await call(AA.cookie, 'PATCH', `/api/dashboard-users/${idSuper}`, { full_name: 'hax' })).status === 404);
    check('A admin cannot modify a user of B -> 404', (await call(AA.cookie, 'PATCH', `/api/dashboard-users/${idBA}`, { is_active: false })).status === 404);
    check('A admin cannot change own role -> 400', (await call(AA.cookie, 'PATCH', `/api/dashboard-users/${idAA}`, { role: 'viewer' })).status === 400);
    check('A admin cannot disable self -> 400', (await call(AA.cookie, 'PATCH', `/api/dashboard-users/${idAA}`, { is_active: false })).status === 400);
    check('A admin cannot delete self -> 400', (await call(AA.cookie, 'DELETE', `/api/dashboard-users/${idAA}`)).status === 400);
    check('A admin cannot promote to super admin -> 403', (await call(AA.cookie, 'PATCH', `/api/dashboard-users/${nv.body.id}`, { role: 'super_admin' })).status === 403);
    check('super cannot disable self -> 400', (await call(S.cookie, 'PATCH', `/api/dashboard-users/${idSuper}`, { is_active: false })).status === 400);
    const pwReset = await call(AA.cookie, 'PATCH', `/api/dashboard-users/${nv.body.id}`, { password: 'brandnewpass1' });
    check('admin resets a user password', pwReset.status === 200 && (await login('a_new_view', 'brandnewpass1')).status === 200 && (await login('a_new_view', 'longpassword')).status === 401);

    section('7b. per-door restriction (and it can never widen by accident)');
    const gs = await call(S.cookie, 'POST', '/api/devices/generate-serial');
    const d5res = await call(S.cookie, 'POST', '/api/devices', { serial: gs.body.serial, mqtt_id: 'D5', name: 'D5', org_id: A });
    check('super creates a device already assigned to a customer', d5res.status === 200 && d5res.body.org_id === A);
    const d5 = d5res.body.id;
    const nvLogin = await login('a_new_view', 'brandnewpass1');
    check('new viewer sees all 3 doors of A', (await call(nvLogin.cookie, 'GET', '/api/devices')).body.length === 3);
    check('restriction to a door of B is refused -> 400', (await call(AA.cookie, 'PUT', `/api/dashboard-users/${nv.body.id}/devices`, { restricted: true, device_ids: [d3] })).status === 400);
    check('restrict viewer to D5 only', (await call(AA.cookie, 'PUT', `/api/dashboard-users/${nv.body.id}/devices`, { restricted: true, device_ids: [d5] })).status === 200);
    const nvAfter = await login('a_new_view', 'brandnewpass1');
    check('viewer now sees only D5', (await call(nvAfter.cookie, 'GET', '/api/devices')).body.map(x => x.id).join() === String(d5));
    check('GET restriction reports it', (await call(AA.cookie, 'GET', `/api/dashboard-users/${nv.body.id}/devices`)).body.restricted === true);
    check('restriction does not apply to an org admin -> 400', (await call(AA.cookie, 'PUT', `/api/dashboard-users/${idAA}/devices`, { restricted: true, device_ids: [d1] })).status === 400);
    await call(S.cookie, 'DELETE', `/api/devices/${d5}`);
    check('after the only allowed door is deleted the user sees NOTHING (access is not widened)', (await call(nvAfter.cookie, 'GET', '/api/devices')).body.length === 0);
    check('removing the restriction gives all doors back', (await call(AA.cookie, 'PUT', `/api/dashboard-users/${nv.body.id}/devices`, { restricted: false })).status === 200
        && (await call((await login('a_new_view', 'brandnewpass1')).cookie, 'GET', '/api/devices')).body.length === 2);

    /* ============ 8. device assignment ============ */
    section('8. assigning devices to customers');
    check('org admin cannot assign devices -> 403', (await call(AA.cookie, 'PATCH', `/api/devices/${d1}/org`, { org_id: B })).status === 403);
    check('A admin does not see unassigned D4', !serials(await call(AA.cookie, 'GET', '/api/devices')).includes('D4'));
    const orphanDU = (await one("INSERT INTO door_users(name,org_id) VALUES('Orphan',NULL) RETURNING id")).id;
    await q("INSERT INTO user_credentials(user_id,device_id,type,identifier,cred_data) VALUES($1,$2,'rfid','Orphan','ORPHANUID')", [orphanDU, d4]);
    const asg = await call(S.cookie, 'PATCH', `/api/devices/${d4}/org`, { org_id: A });
    check('super assigns D4 to customer A', asg.status === 200 && asg.body.org_id === A);
    check('...existing door user of that device was adopted by A', asg.body.adopted.door_users === 1 && (await one('SELECT org_id FROM door_users WHERE id=$1', [orphanDU])).org_id === A);
    check('A admin now sees D4', serials(await call(AA.cookie, 'GET', '/api/devices')).includes('D4'));
    check('moving a device that still has customer data is refused -> 409', (await call(S.cookie, 'PATCH', `/api/devices/${d4}/org`, { org_id: B })).status === 409);
    await q('DELETE FROM user_credentials WHERE device_id = $1', [d4]);
    check('after the data is removed it can move to customer B', (await call(S.cookie, 'PATCH', `/api/devices/${d4}/org`, { org_id: B })).status === 200
        && serials(await call(BA.cookie, 'GET', '/api/devices')).includes('D4'));
    check('unknown customer -> 400', (await call(S.cookie, 'PATCH', `/api/devices/${d4}/org`, { org_id: 99999 })).status === 400);

    /* ============ 9. disabling a customer ============ */
    section('9. disabling a customer cuts it off immediately');
    const Z = (await call(S.cookie, 'POST', '/api/orgs', { name: 'Customer Z' })).body.id;
    await call(S.cookie, 'POST', '/api/dashboard-users', { username: 'z_admin', password: 'longpassword', role: 'org_admin', org_id: Z });
    await q("INSERT INTO app_users(username,password,full_name,org_id) VALUES('app_z',$1,'Z',$2)", [hash, Z]);
    const ZA = await login('z_admin', 'longpassword');
    const zws = await wsConnect(ZA.cookie);
    const zMobile = await (await fetch(base + '/api/app/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'app_z', password: 'pw123456' }) })).json();
    check('Z admin works and is connected live', (await call(ZA.cookie, 'GET', '/api/me')).status === 200 && zws.status === 101);
    await call(S.cookie, 'PATCH', `/api/orgs/${Z}`, { is_active: false });
    await sleep(200);
    check('Z admin: next request -> 401', (await call(ZA.cookie, 'GET', '/api/me')).status === 401);
    check('Z admin: cannot log in again', (await login('z_admin', 'longpassword')).status === 401);
    check('Z admin: live WebSocket closed', zws.closedCode === 4401);
    const zKeys = await fetch(base + '/api/app/keys', { headers: { authorization: 'Bearer ' + zMobile.token } });
    check('Z mobile user: existing token no longer gets keys', zKeys.status === 401);
    const zLogin = await fetch(base + '/api/app/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'app_z', password: 'pw123456' }) });
    check('Z mobile user: cannot log in again', zLogin.status === 401);

    /* ============ 10. WebSocket ============ */
    section('10. WebSocket: login required, events filtered per customer');
    check('no cookie -> 401', (await wsConnect(null)).status === 401);
    check('bad cookie -> 401', (await wsConnect('connect.sid=garbage')).status === 401);
    check('cross-site origin -> 403', (await wsConnect(AA.cookie, 'https://evil.example')).status === 403);

    const wsS = await wsConnect(S.cookie), wsAA = await wsConnect(AA.cookie), wsAV = await wsConnect((await login('a_view')).cookie);
    const wsAO2 = await wsConnect((await login('a_op2')).cookie), wsBA = await wsConnect(BA.cookie);
    check('valid sessions connect', [wsS, wsAA, wsAV, wsAO2, wsBA].every(c => c.status === 101));
    for (const [type, id] of [['heartbeat', d1], ['heartbeat', d2], ['heartbeat', d3], ['wifi', d1], ['event', d1], ['logs', d3], ['mystery', d1]])
        hub.broadcast({ type, serial: 'x', deviceId: id, data: {} });
    hub.broadcast({ type: 'heartbeat', serial: 'nodev', data: {} });      /* no deviceId */
    await sleep(300);
    check('super receives everything', got(wsS, 'heartbeat', d3) && got(wsS, 'mystery', d1) && wsS.msgs.length === 8);
    check('A admin receives only customer A events', got(wsAA, 'heartbeat', d1) && got(wsAA, 'heartbeat', d2) && got(wsAA, 'wifi', d1) && !got(wsAA, 'heartbeat', d3) && !got(wsAA, 'logs', d3));
    check('A admin does not receive unknown event types or device-less events', !got(wsAA, 'mystery', d1) && wsAA.msgs.length === 4);
    check('viewer gets status/logs but not Wi-Fi events', got(wsAV, 'heartbeat', d1) && got(wsAV, 'event', d1) && !got(wsAV, 'wifi', d1));
    check('restricted operator receives only its door', got(wsAO2, 'heartbeat', d1) && !got(wsAO2, 'heartbeat', d2));
    check('B admin receives only B events', got(wsBA, 'heartbeat', d3) && got(wsBA, 'logs', d3) && !got(wsBA, 'heartbeat', d1));

    section('10b. WebSocket: sessions are revoked');
    await q("UPDATE users SET role = 'viewer' WHERE id = $1", [idAO]);
    const wsAO = await wsConnect(AO.cookie);
    check('connected operator (before demotion) is open', wsAO.status === 101);
    await q("UPDATE users SET is_active = FALSE WHERE id = $1", [idAO]);
    await sleep(1200);
    check('disabling a user in the DB closes their socket within the re-validation interval', wsAO.closedCode === 4401);
    const wsLogout = await wsConnect(AV.cookie);
    await call(AV.cookie, 'GET', '/api/logout');
    await sleep(200);
    check('logout closes the socket at once', wsLogout.closedCode === 4401);
    check('after logout the cookie is dead', (await call(AV.cookie, 'GET', '/api/devices')).status === 401);

    /* ============ 11. audit trail ============ */
    section('11. audit trail');
    check('operator cannot read the audit trail -> 403', (await call(AO2.cookie, 'GET', '/api/audit')).status === 403);
    const aAudit = await call(AA.cookie, 'GET', '/api/audit?limit=200');
    check('A admin sees only A entries', aAudit.status === 200 && aAudit.body.length > 0 && aAudit.body.every(r => r.org_id === A));
    const sAudit = await call(S.cookie, 'GET', '/api/audit?limit=200');
    check('super sees entries of several customers', new Set(sAudit.body.map(r => r.org_id)).size >= 2);
    const actions = new Set(sAudit.body.map(r => r.action));
    check('commands, credentials, users and assignments are recorded', ['device.command', 'credential.add', 'user.create', 'device.assign', 'org.create'].every(a => actions.has(a)));
    const blob = JSON.stringify(sAudit.body);
    check('audit never contains secrets (credential, Wi-Fi password, passwords, PIN)',
        !blob.includes('SECRET-PIN-9876') && !blob.includes('wifi-secret-xyz') && !blob.includes('longpassword') && !blob.includes('brandnewpass1'));
    check('audit records who did it', sAudit.body.some(r => r.username === 'a_admin' && r.action === 'credential.add'));

    /* ============ 12. page guards ============ */
    section('12. HTML page guards');
    const anon = await call(null, 'GET', '/admin.html');
    check('anonymous -> admin.html redirects to login', anon.status === 302 && /login/.test(anon.headers.get('location') || ''));
    const anonStatic = await call(null, 'GET', '/users.html');
    check('anonymous -> users.html redirects to login', anonStatic.status === 302);
    const SS = await login('super');
    check('super opens admin.html', (await call(SS.cookie, 'GET', '/admin.html')).status === 200);
    const aa = await login('a_admin');
    check('customer admin opens admin.html', (await call(aa.cookie, 'GET', '/admin.html')).status === 200);
    check('customer admin may NOT open serials.html (redirect)', (await call(aa.cookie, 'GET', '/serials.html')).status === 302);
    check('customer admin may NOT open tempqr.html (redirect)', (await call(aa.cookie, 'GET', '/tempqr.html')).status === 302);
    const vv = await login('a_view');
    check('viewer opens dashboard', (await call(vv.cookie, 'GET', '/')).status === 200);
    check('viewer may NOT open admin.html', (await call(vv.cookie, 'GET', '/admin.html')).status === 302);
    check('viewer may NOT open users.html', (await call(vv.cookie, 'GET', '/users.html')).status === 302);
    check('login page and shared script are public', (await call(null, 'GET', '/login.html')).status === 200 && (await call(null, 'GET', '/js/rbac.js')).status === 200);

    /* ============ 13. device security (protocol v2) ============ */
    section('13. device security: legacy vs per-device keys');
    const sig = require(path.join(ROOT, 'src/devicesig'));
    const crypto = require('crypto');
    const S3 = await login('super'), AA3 = await login('a_admin'), BA3 = await login('b_admin'), AV3 = await login('a_view');
    const devRow = async id => (await one('SELECT * FROM devices WHERE id = $1', [id]));
    const lastPub = () => published[published.length - 1];
    const cmd3 = (c, serial, name, extra = {}) => call(c, 'POST', '/api/devices/command', { serial, cmd: name, ts: Math.floor(Date.now() / 1000), ...extra });

    check('devices start on protocol v1', (await devRow(d1)).key_version === 1);

    published.length = 0;
    await cmd3(AA3.cookie, 'D1', 'open');
    const v1p = lastPub().msg;
    check('v1 device: legacy message (no v/nonce), signature over cmd:ts',
        v1p.v === undefined && v1p.n === undefined &&
        v1p.hmac === crypto.createHmac('sha256', 'test-mqtt-secret').update(`open:${v1p.ts}`).digest('hex'));

    check('customer admin cannot mark a device v2 -> 403', (await call(AA3.cookie, 'POST', `/api/devices/${d1}/mark-v2`)).status === 403);
    check('customer admin cannot export provisioning -> 403', (await call(AA3.cookie, 'POST', `/api/devices/${d1}/provision`, {})).status === 403);
    check('customer admin cannot migrate -> 403', (await call(AA3.cookie, 'POST', `/api/devices/${d1}/migrate`)).status === 403);

    /* migration of a legacy device */
    published.length = 0;
    const mig = await call(S3.cookie, 'POST', `/api/devices/${d3}/migrate`);
    const migMsg = lastPub() && lastPub().msg;
    check('super migrates a legacy device -> 200', mig.status === 200);
    check('migration command: legacy-signed provision_v2 carrying that device key only',
        migMsg && migMsg.cmd === 'provision_v2' && lastPub().topic === 'adc100/D3/cmd' &&
        migMsg.dev_key === sig.deviceKey(await devRow(d3)).toString('hex') &&
        migMsg.hmac === crypto.createHmac('sha256', 'test-mqtt-secret').update(`provision_v2:${migMsg.ts}`).digest('hex'));
    check('device keys differ per device', sig.deviceKey(await devRow(d1)).toString('hex') !== sig.deviceKey(await devRow(d3)).toString('hex'));
    check('...and the dashboard does not switch to v2 before the device confirms', (await devRow(d3)).key_version === 1);

    const exp1 = await call(S3.cookie, 'POST', `/api/devices/${d1}/provision`, { mqtt_uri: 'mqtts://b.example:8883', mqtt_user: 'u1', mqtt_pass: 'p1' });
    const keyHex = sig.deviceKey(await devRow(d1)).toString('hex');
    check('super exports provisioning (key + NVS csv)', exp1.status === 200 && exp1.body.key_hex === keyHex &&
        exp1.body.nvs_csv.includes(`dev_key,data,hex2bin,${keyHex}`) && exp1.body.nvs_csv.includes('mqtt_uri,data,string,mqtts://b.example:8883'));

    await call(S3.cookie, 'POST', `/api/devices/${d1}/mark-v2`);
    check('device D1 is now v2', (await devRow(d1)).key_version === 2);
    check('mark-v2 again on a v2 device still fine, migrate refuses -> 409', (await call(S3.cookie, 'POST', `/api/devices/${d1}/migrate`)).status === 409);

    /* commands to a v2 device */
    const verify2 = (m, device, cmdName, fields) => m.v === 2 && /^[0-9a-f]{16}$/.test(m.n) &&
        m.hmac === crypto.createHmac('sha256', sig.deviceKey(device)).update(sig.v2Message(device.mqtt_id || device.serial, cmdName, m.ts, m.n, fields)).digest('hex');
    const D1row = await devRow(d1);

    published.length = 0;
    await cmd3(AA3.cookie, 'D1', 'open');
    const o2 = lastPub().msg;
    check('v2 open: per-device signature with relay fields', verify2(o2, D1row, 'open', { relay_mode: o2.relay_mode, relay_duration: o2.relay_duration }));
    check('v2 open: server time is used (client ts ignored)', Math.abs(o2.ts - Math.floor(Date.now() / 1000)) <= 2);

    published.length = 0;
    await cmd3(S3.cookie, 'D1', 'ota_update', { url: 'https://example.com/fw.bin' });
    const ota2 = lastPub().msg;
    check('v2 ota_update: the URL is covered by the signature', verify2(ota2, D1row, 'ota_update', { url: 'https://example.com/fw.bin' }) &&
        !verify2({ ...ota2, hmac: ota2.hmac }, D1row, 'ota_update', { url: 'https://evil.example/fw.bin' }));

    published.length = 0;
    await cmd3(AA3.cookie, 'D1', 'set_wifi', { ssid: 'Net', password: 'secretpass' });
    const w2 = lastPub().msg;
    check('v2 set_wifi uses the firmware field "pass"', w2.pass === 'secretpass' && verify2(w2, D1row, 'set_wifi', { ssid: 'Net', pass: 'secretpass' }));

    published.length = 0;
    await call(AA3.cookie, 'POST', `/api/credentials/${d1}`, { label: 'k2', cred_type: 'pin', cred_data: '4321' });
    const c2 = lastPub().msg;
    check('v2 add_credential: data fields signed', verify2(c2, D1row, 'add_credential', { cred_type: 'pin', cred_data: '4321', label: 'k2', duress: 'false' }));

    published.length = 0;
    await cmd3(AA3.cookie, 'D1', 'get_logs');
    const n1 = lastPub().msg.n;
    await cmd3(AA3.cookie, 'D1', 'get_logs');
    check('every v2 command carries a fresh nonce', lastPub().msg.n !== n1);

    check('another customer still gets 404 for the v2 door', (await cmd3(BA3.cookie, 'D1', 'open')).status === 404);

    /* temporary QR per door */
    const now = Date.now();
    const qrBody = { iat: new Date(now).toISOString(), exp: new Date(now + 3600e3).toISOString() };
    const qr = await call(AA3.cookie, 'POST', `/api/devices/${d1}/temp-qr`, qrBody);
    const qrObj = qr.body && qr.body.qr_text ? JSON.parse(qr.body.qr_text) : {};
    check('customer admin creates a temporary QR for their v2 door', qr.status === 200 && qrObj.v === 2 && qrObj.did === 'D1');
    check('QR text starts with the prefix the firmware looks for', qr.body.qr_text.startsWith('{"v":2,'));
    check('QR signature = HMAC(device key) over the door id', qrObj.hmac === crypto.createHmac('sha256', sig.deviceKey(D1row)).update(`v2tqr\nD1\n${qrObj.iat}\n${qrObj.exp}`).digest('hex'));
    check('QR for a legacy door is refused -> 409', (await call(AA3.cookie, 'POST', `/api/devices/${d2}/temp-qr`, qrBody)).status === 409);
    check('QR for another customer door -> 404', (await call(AA3.cookie, 'POST', `/api/devices/${d3}/temp-qr`, qrBody)).status === 404);
    check('other customer cannot make a QR for D1 -> 404', (await call(BA3.cookie, 'POST', `/api/devices/${d1}/temp-qr`, qrBody)).status === 404);
    check('viewer cannot make a QR -> 403', (await call(AV3.cookie, 'POST', `/api/devices/${d1}/temp-qr`, qrBody)).status === 403);
    check('QR longer than 7 days refused -> 400', (await call(AA3.cookie, 'POST', `/api/devices/${d1}/temp-qr`, { iat: qrBody.iat, exp: new Date(now + 8 * 86400e3).toISOString() })).status === 400);
    check('QR with exp before iat refused -> 400', (await call(AA3.cookie, 'POST', `/api/devices/${d1}/temp-qr`, { iat: qrBody.exp, exp: qrBody.iat })).status === 400);

    /* BLE keys handed to the mobile app */
    await q('INSERT INTO user_door_access(user_id,device_id) VALUES($1,$2) ON CONFLICT DO NOTHING', [auA, d1]);
    const appLogin = await fetch(base + '/api/app/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'app_a', password: 'pw123456' }) });
    const appBody = await appLogin.json();
    check('v2 door: the app receives a key derived for that door only',
        appBody.keys && appBody.keys.D1 === 'hex:' + sig.bleKey(D1row).toString('hex'));
    check('BLE key differs from the device key', appBody.keys.D1 !== 'hex:' + sig.deviceKey(D1row).toString('hex'));

    /* audit: provisioning actions are recorded, the key never is */
    const aud3 = await call(S3.cookie, 'GET', '/api/audit?limit=200');
    const acts3 = new Set(aud3.body.map(r => r.action));
    check('audit records migrate / provisioning export / mark_v2 / temp QR',
        ['device.migrate', 'device.provision.export', 'device.mark_v2', 'device.tempqr'].every(a => acts3.has(a)));
    check('audit never contains device keys', !JSON.stringify(aud3.body).includes(keyHex));

    /* ============ summary ============ */
    console.log(`\n${pass} passed, ${fail} failed`);
    if (fail) console.log('Failed:\n - ' + failures.join('\n - '));
    [wsS, wsAA, wsAV, wsAO2, wsBA, wsAO, wsLogout, zws].forEach(c => { try { c.ws.terminate(); } catch (_) {} });
    server.close();
    await pool.end();
    process.exit(fail ? 1 : 0);
})().catch(err => { console.error('TEST ERROR', err); process.exit(2); });
