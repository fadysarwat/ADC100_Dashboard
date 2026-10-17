const mqtt   = require('mqtt');
const pool   = require('./db/pool');
require('dotenv').config();

let client    = null;
let broadcast = null;

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
            console.error('MQTT parse error:', err.message);
            return;
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

            const evResult = await pool.query(
                `INSERT INTO access_logs (device_id, method, result)
                VALUES ($1, $2, $3) RETURNING *`,
                [device.id, method, payload.result]
            );

                console.log(`Access event from ${mqttId} — ${payload.method}: ${payload.result}`);

                if (broadcast) {
                    broadcast({
                        type:     'event',
                        serial:   mqttId,
                        deviceId: device.id,
                        data:     evResult.rows[0]
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

module.exports = { startMqtt, publish };