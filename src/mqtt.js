const mqtt   = require('mqtt');
const pool   = require('./db/pool');
const { markSeen, openOutage } = require('./presence');
require('dotenv').config();

let client    = null;
let broadcast = null;

/* Firmware sometimes logs raw JSON inside msg values without proper escaping.
   This parser attempts standard JSON.parse first, then falls back to a
   field-by-field extractor that tolerates unescaped quotes in msg strings. */
function parseLogsPayload(rawStr) {
    try { return JSON.parse(rawStr); } catch (_) {}

    const event = (rawStr.match(/"event"\s*:\s*"([^"]*)"/) || [])[1];
    const total = parseInt((rawStr.match(/"total"\s*:\s*(\d+)/) || [])[1] || '0');
    const entries = [];

    /* Split entries by locating each {"lvl": header. Because msg values may
       contain unescaped " and nested {}, we cannot rely on JSON structure.
       Strategy: find every position where a new entry starts ({"lvl":), then
       slice the raw string between consecutive starts and extract fields. */
    const starts = [];
    const startRe = /\{(?="lvl"\s*:)/g;
    let sm;
    while ((sm = startRe.exec(rawStr)) !== null) starts.push(sm.index);

    for (let i = 0; i < starts.length; i++) {
        const chunk = rawStr.slice(starts[i], starts[i + 1] ?? rawStr.length);
        const lvl = (chunk.match(/"lvl"\s*:\s*"([^"]*)"/) || [])[1] || 'I';
        const ts  = parseInt((chunk.match(/"ts"\s*:\s*(\d+)/) || [])[1] || '0');
        const up  = parseInt((chunk.match(/"up"\s*:\s*(\d+)/) || [])[1] || '0');
        const tag = (chunk.match(/"tag"\s*:\s*"([^"]*)"/) || [])[1] || '';
        /* msg: everything after "msg":" to end of chunk.
           Strip the LAST occurrence of "} (or "}]) that closes the entry,
           leaving any embedded JSON in msg intact. */
        const msgM = chunk.match(/"msg"\s*:\s*"([\s\S]*)/);
        let msg = msgM ? msgM[1] : '';
        /* Remove last "}  closing sequence: last " then optional whitespace/},] */
        msg = msg.replace(/"[}\]\s,]*$/, '').replace(/\\"/g, '"');
        entries.push({ lvl, ts, up, tag, msg });
    }

    console.warn(`MQTT logs parse recovered via fallback — entries:${entries.length}`);
    return { event, total, entries };
}

function startMqtt(broadcastFn) {
    broadcast = broadcastFn;

    client = mqtt.connect(process.env.MQTT_BROKER, {
        port:     parseInt(process.env.MQTT_PORT),
        username: process.env.MQTT_USERNAME,
        password: process.env.MQTT_PASSWORD,
        protocol: 'mqtts',
    });

    client.on('connect', () => {
        console.log('MQTT connected to HiveMQ');
        client.subscribe('adc100/+/heartbeat');
        client.subscribe('adc100/+/status');
        client.subscribe('adc100/+/event');
    });

    client.on('message', async (topic, message) => {
        const parts    = topic.split('/');
        const mqttId   = parts[1];
        const type     = parts[2];

        let payload;
        try {
            payload = JSON.parse(message.toString());
        } catch (err) {
            /* Standard parse failed — could be a logs event with unescaped msg content.
               Peek at the raw string: if it looks like a logs event, use the tolerant
               parseLogsPayload(); otherwise give up. */
            const raw = message.toString();
            if (raw.includes('"event":"logs"') || raw.includes('"event": "logs"')) {
                payload = parseLogsPayload(raw);
                if (!payload.event) {
                    console.error('MQTT parse error (logs fallback also failed):', err.message);
                    return;
                }
            } else {
                console.error('MQTT parse error:', err.message);
                return;
            }
        }

        try {
            /* البحث بالـ mqtt_id أولاً، لو مش لاقي يبحث بالـ serial */
            let devResult = await pool.query(
                'SELECT * FROM devices WHERE mqtt_id = $1',
                [mqttId]
            );
            if (devResult.rows.length === 0) {
                devResult = await pool.query(
                    'SELECT * FROM devices WHERE serial = $1',
                    [mqttId]
                );
            }
            if (devResult.rows.length === 0) {
                console.warn(`Device not found: ${mqttId}`);
                return;
            }
            const device = devResult.rows[0];

            if (type === 'heartbeat') {
                await pool.query(
                    'UPDATE devices SET status = $1, activated = TRUE WHERE id = $2',
                    ['online', device.id]
                );
                await markSeen(device.id);

                const hbResult = await pool.query(
                    `INSERT INTO heartbeats
                        (device_id, fw, uptime, rssi, ip, free_heap, door, relay, tamper, fire,
                         restart_reason, credentials, schedule_enabled, schedule_start, schedule_end, mqtt_reconnects)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
                    [device.id, payload.fw, payload.uptime, payload.rssi,
                     payload.ip, payload.free_heap, payload.door,
                     payload.relay, payload.tamper, payload.fire,
                     payload.restart_reason   ?? null,
                     payload.credentials      ?? null,
                     payload.schedule_enabled ?? null,
                     payload.schedule_start   ?? null,
                     payload.schedule_end     ?? null,
                     payload.mqtt_reconnects  ?? null]
                );

                console.log(`Heartbeat from ${mqttId} — uptime: ${payload.uptime}s — row id: ${hbResult.rows[0].id}`);

                /* Keep only last 100 heartbeats per device */
                await pool.query(
                    `DELETE FROM heartbeats WHERE device_id = $1 AND id NOT IN (
                        SELECT id FROM heartbeats WHERE device_id = $1
                        ORDER BY created_at DESC LIMIT 100
                    )`,
                    [device.id]
                );

                if (broadcast) {
                    broadcast({
                        type:     'heartbeat',
                        serial:   mqttId,
                        deviceId: device.id,
                        data:     payload
                    });
                }
            }

            if (type === 'status') {
                await pool.query(
                    'UPDATE devices SET status = $1 WHERE id = $2',
                    [payload.status === 'online' ? 'online' : 'offline', device.id]
                );
                if (payload.status === 'online') await markSeen(device.id);
                else await openOutage(device.id, device.last_seen);

                if (broadcast) {
                    broadcast({
                        type:     'status',
                        serial:   mqttId,
                        deviceId: device.id,
                        data:     payload
                    });
                }
            }

            if (type === 'event') {

                /* WiFi events — broadcast only, no DB insert */
                if (payload.event === 'wifi') {
                    console.log(`WiFi event from ${mqttId} — cmd: ${payload.cmd}, result: ${payload.result}`);
                    if (broadcast) {
                        broadcast({
                            type:     'wifi',
                            serial:   mqttId,
                            deviceId: device.id,
                            data:     payload
                        });
                    }
                    return;
                }

                /* Provisioning ACK: the device stored its per-device key and now
                   accepts v2 only, so from here on the dashboard signs with v2. */
                if (payload.event === 'provision') {
                    console.log(`Provision event from ${mqttId} — result: ${payload.result}`);
                    if (payload.result === 'OK' || payload.result === 'ALREADY') {
                        pool.query('UPDATE devices SET key_version = 2 WHERE id = $1', [device.id])
                            .catch(e => console.error('key_version update failed:', e.message));
                    }
                    return;
                }

                /* Credential events (add/delete ACK) — ignore, no DB insert */
                if (payload.event === 'credential') {
                    console.log(`Credential event from ${mqttId} — cmd: ${payload.cmd}, label: ${payload.label}, result: ${payload.result}`);
                    return;
                }

                /* ── Logs event — broadcast to dashboard, no DB insert ── */
                if (payload.event === 'logs') {
                    console.log(`Logs event from ${mqttId} — total: ${payload.total}, entries: ${(payload.entries || []).length}`);
                    if (broadcast) {
                        broadcast({
                            type:     'logs',
                            serial:   mqttId,
                            deviceId: device.id,
                            data:     payload
                        });
                    }
                    return;
                }

                /* Access events — save to DB and broadcast */
                let method = payload.method;

                /* Check if PIN is a temp PIN */
                if (method === 'PIN' && payload.result === 'GRANTED') {
                    const tempCheck = await pool.query(
                        `SELECT id FROM temp_pins
                        WHERE device_id = $1
                        AND active = TRUE
                        AND NOW() BETWEEN iat AND exp`,
                        [device.id]
                    );
                    if (tempCheck.rows.length > 0) {
                        method = 'TEMP_PIN';
                    }
                }

                /* Lookup door_user_id from identifier if present (RFID / PIN / QR) */
                let doorUserId = null;
                if (payload.identifier && method !== 'BLE') {
                    const userCheck = await pool.query(
                        `SELECT uc.user_id FROM user_credentials uc
                         JOIN door_users du ON du.id = uc.user_id
                         WHERE uc.device_id = $1
                         AND uc.identifier = $2
                         AND du.active = TRUE
                         LIMIT 1`,
                        [device.id, payload.identifier]
                    );
                    if (userCheck.rows.length > 0) {
                        doorUserId = userCheck.rows[0].user_id;
                    }
                }

                const evResult = await pool.query(
                    `INSERT INTO access_logs (device_id, method, result, door_user_id)
                    VALUES ($1, $2, $3, $4) RETURNING *`,
                    [device.id, method, payload.result, doorUserId]
                );

                console.log(`Access event from ${mqttId} — ${payload.method}: ${payload.result}`);

                /* Fetch log row with user_name for live broadcast */
                const logWithUser = await pool.query(
                    `SELECT al.*, du.name AS user_name
                     FROM access_logs al
                     LEFT JOIN door_users du ON du.id = al.door_user_id
                     WHERE al.id = $1`,
                    [evResult.rows[0].id]
                );

                /* BLE access — identifier is the app username, not a door_user */
                const rowData = logWithUser.rows[0];
                if (method === 'BLE' && payload.identifier) {
                    rowData.user_name = payload.identifier;
                }

                if (broadcast) {
                    broadcast({
                        type:     'event',
                        serial:   mqttId,
                        deviceId: device.id,
                        data:     rowData
                    });
                }
            }

        } catch (err) {
            console.error('MQTT message error:', err.message);
            console.error(err.stack);
        }
    });

    client.on('error', (err) => {
        console.error('MQTT error:', err.message);
    });
}

function publish(topic, message) {
    if (!client) {
        console.error('MQTT client not initialized');
        return;
    }
    client.publish(topic, message, { qos: 1 });
    console.log(`MQTT published to ${topic}: ${message}`);
}

/**
 * sendGetLogs / sendClearLogs — signed commands (v1 or v2 by device.key_version).
 * @param {{mqtt_id?:string, serial?:string, key_version?:number}} device
 */
function sendSimple(device, cmd) {
    if (!client) return false;
    const { buildCommand } = require('./devicesig');
    const mqttId = device.mqtt_id || device.serial;
    client.publish(`adc100/${mqttId}/cmd`, JSON.stringify(buildCommand(device, cmd)), { qos: 1 });
    console.log(`${cmd} sent to ${mqttId}`);
    return true;
}
const sendGetLogs   = (device) => sendSimple(device, 'get_logs');
const sendClearLogs = (device) => sendSimple(device, 'clear_logs');

module.exports = { startMqtt, publish, sendGetLogs, sendClearLogs };
