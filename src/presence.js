/* Presence helpers: "last seen" and the history of outages of a device.
   Times come from the server clock, never from the device clock. */
const pool = require('./db/pool');

/* The device was heard from just now: refresh last_seen and close an open outage. */
async function markSeen(deviceId) {
    await pool.query('UPDATE devices SET last_seen = NOW() WHERE id = $1', [deviceId]);
    await pool.query(
        'UPDATE device_outages SET ended_at = NOW() WHERE device_id = $1 AND ended_at IS NULL',
        [deviceId]
    );
}

/* The device went quiet. The outage starts at the last time it was heard from. */
async function openOutage(deviceId, lastSeen) {
    await pool.query(
        `INSERT INTO device_outages (device_id, started_at)
         VALUES ($1, COALESCE($2, NOW()))
         ON CONFLICT (device_id) WHERE ended_at IS NULL DO NOTHING`,
        [deviceId, lastSeen]
    );
}

/* Devices that are "online" but sent no heartbeat for 5 minutes become offline. */
async function detectOffline() {
    const result = await pool.query(
        `UPDATE devices SET status = 'offline'
         WHERE status = 'online'
         AND id NOT IN (
             SELECT DISTINCT device_id FROM heartbeats
             WHERE created_at > NOW() - INTERVAL '5 minutes'
         )
         RETURNING id, serial, last_seen`
    );
    for (const d of result.rows) await openOutage(d.id, d.last_seen);
    return result.rows;
}

module.exports = { markSeen, openOutage, detectOffline };
