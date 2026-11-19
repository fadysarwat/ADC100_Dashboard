/* ============================================================
   Secure WebSocket hub.

   Before: anyone could connect (no login check) and every client
   received the events of EVERY device; the page merely ignored
   what was not its own.

   Now:
   1. The handshake is authenticated with the same session cookie as
      the website. No valid login -> HTTP 401, no WebSocket.
      A cross-site Origin is refused (cross-site WebSocket hijacking).
   2. Every event is delivered ONLY to clients allowed to see that
      device: super_admin sees all; everyone else only devices of
      their own customer, only event types their role allows, and only
      the doors they are restricted to (if any).
   3. Every 30 s each connection is re-validated (user still active,
      customer still active, session still exists, role/restrictions
      refreshed). Logout / disabling closes sockets immediately via
      disconnectSession / disconnectUser / disconnectOrg.
   ============================================================ */
const http      = require('http');
const WebSocket = require('ws');
const pool      = require('./db/pool');
const { hasPerm, loadUserById, loadDeviceRestriction } = require('./auth');

/* Event type -> permission needed to receive it. Unknown types are
   delivered to super_admin only (deny by default). */
const EVENT_PERMS = {
    heartbeat: 'device.view',
    status:    'device.view',
    event:     'logs.view',        /* access events (who opened the door) */
    logs:      'logs.view',        /* device log dump */
    wifi:      'device.configure'  /* Wi-Fi provisioning events */
};

const REVALIDATE_MS   = parseInt(process.env.WS_REVALIDATE_MS, 10) || 30 * 1000;
const DEVICE_ORG_TTL  = 30 * 1000;

function createHub() {
    const wss = new WebSocket.Server({ noServer: true, maxPayload: 1024 });

    /* deviceId -> { org, t }  (small cache: avoids one query per event) */
    const deviceOrg = new Map();
    async function getDeviceOrg(deviceId) {
        const hit = deviceOrg.get(deviceId);
        if (hit && Date.now() - hit.t < DEVICE_ORG_TTL) return hit.org;
        const r = await pool.query('SELECT org_id FROM devices WHERE id = $1', [deviceId]);
        const org = r.rows.length ? r.rows[0].org_id : undefined;   /* undefined = no such device */
        deviceOrg.set(deviceId, { org, t: Date.now() });
        return org;
    }

    function canReceive(ws, data, org) {
        const u = ws.user;
        if (!u) return false;
        if (u.role === 'super_admin') return true;

        const perm = EVENT_PERMS[data.type];
        if (!perm || !hasPerm(u.role, perm)) return false;
        if (data.deviceId === undefined || data.deviceId === null) return false;
        if (org === undefined || org === null || org !== u.orgId) return false;
        if (ws.restrictedTo && !ws.restrictedTo.has(data.deviceId)) return false;
        return true;
    }

    /* Events are delivered one after another so their order is preserved
       even though the ownership lookup is asynchronous. */
    let queue = Promise.resolve();
    function broadcast(data) {
        queue = queue.then(async () => {
            let org;
            if (data.deviceId !== undefined && data.deviceId !== null) {
                try { org = await getDeviceOrg(data.deviceId); }
                catch (err) { console.error('ws org lookup failed:', err.message); return; }
            }
            const payload = JSON.stringify(data);
            wss.clients.forEach(ws => {
                if (ws.readyState === WebSocket.OPEN && canReceive(ws, data, org)) ws.send(payload);
            });
        }).catch(err => console.error('ws broadcast failed:', err.message));
    }

    /* ── Authenticated upgrade ── */
    function attach(server, sessionMiddleware) {
        server.on('upgrade', (req, socket, head) => {
            const reject = (code, text) => {
                socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
                socket.destroy();
            };

            /* Cross-site WebSocket hijacking guard */
            const origin = req.headers.origin;
            if (origin) {
                let originHost = null;
                try { originHost = new URL(origin).host; } catch (_) { /* invalid */ }
                if (originHost !== req.headers.host) return reject(403, 'Forbidden');
            }

            /* Run the normal session middleware against the handshake request */
            const res = new http.ServerResponse(req);
            sessionMiddleware(req, res, async (err) => {
                if (err) return reject(500, 'Session error');
                try {
                    const userId = req.session && req.session.userId;
                    const user   = await loadUserById(userId);
                    if (!user) return reject(401, 'Unauthorized');

                    const restrictedTo = await loadDeviceRestriction(user);

                    wss.handleUpgrade(req, socket, head, (ws) => {
                        ws.user         = user;
                        ws.restrictedTo = restrictedTo;
                        ws.sessionID    = req.sessionID;
                        ws.sessionStore = req.sessionStore;
                        ws.isAlive      = true;
                        wss.emit('connection', ws, req);
                    });
                } catch (e) {
                    reject(500, 'Server error');
                }
            });
        });

        wss.on('connection', (ws) => {
            console.log(`Dashboard client connected: ${ws.user.username} (${ws.user.role})`);
            ws.on('message', () => { /* the dashboard never sends anything; ignore */ });
            ws.on('error', () => {});
            ws.on('close', () => console.log(`Dashboard client disconnected: ${ws.user && ws.user.username}`));
        });
    }

    /* ── Revocation ── */
    function disconnectWhere(pred, reason) {
        wss.clients.forEach(ws => { if (pred(ws)) ws.close(4401, reason); });
    }
    const disconnectSession = (sid)   => disconnectWhere(ws => ws.sessionID === sid, 'logged out');
    const disconnectUser    = (uid)   => disconnectWhere(ws => ws.user && ws.user.id === uid, 'user changed');
    const disconnectOrg     = (orgId) => disconnectWhere(ws => ws.user && ws.user.orgId === orgId, 'customer changed');
    const invalidateDevice  = (id)    => { deviceOrg.delete(id); };

    /* Periodic re-validation (covers anything not revoked explicitly). */
    const timer = setInterval(() => {
        wss.clients.forEach(async (ws) => {
            try {
                const user = await loadUserById(ws.user && ws.user.id);
                if (!user) return ws.close(4401, 'unauthorized');

                const sessionOk = await new Promise(resolve => {
                    if (!ws.sessionStore) return resolve(true);
                    ws.sessionStore.get(ws.sessionID, (err, sess) =>
                        resolve(!err && !!sess && sess.userId === user.id));
                });
                if (!sessionOk) return ws.close(4401, 'session ended');

                ws.user         = user;                                  /* role may have changed */
                ws.restrictedTo = await loadDeviceRestriction(user);     /* so may door restrictions */
            } catch (err) {
                console.error('ws revalidate failed:', err.message);
            }
        });
    }, REVALIDATE_MS);
    timer.unref();

    return { wss, attach, broadcast, disconnectSession, disconnectUser, disconnectOrg, invalidateDevice };
}

module.exports = { createHub, EVENT_PERMS };
