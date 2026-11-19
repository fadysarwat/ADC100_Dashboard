const pool    = require('./db/pool');
const { buildCommand } = require('./devicesig');
const crypto  = require('crypto');
const { publish } = require('./mqtt');
require('dotenv').config();

function startMonitor(broadcast) {
    /* Check every 60 seconds */
    setInterval(async () => {
        try {
            /* ── Device offline detection ── */
            const offlineResult = await pool.query(
                `UPDATE devices SET status = 'offline'
                 WHERE status = 'online'
                 AND id NOT IN (
                     SELECT DISTINCT device_id FROM heartbeats
                     WHERE created_at > NOW() - INTERVAL '5 minutes'
                 )
                 RETURNING id, serial`
            );

            offlineResult.rows.forEach(device => {
                console.log(`Device offline: ${device.serial}`);
                if (broadcast) {
                    broadcast({
                        type:     'status',
                        serial:   device.serial,
                        deviceId: device.id,
                        data:     { status: 'offline' }
                    });
                }
            });

            /* ── Expired temp PINs cleanup ── */
            const expiredPins = await pool.query(
                `SELECT tp.*, d.mqtt_id, d.serial, d.key_version
                 FROM temp_pins tp
                 JOIN devices d ON d.id = tp.device_id
                 WHERE tp.active = TRUE AND tp.exp < NOW()`
            );

            for (const pin of expiredPins.rows) {
                const mqtt_id = pin.mqtt_id || pin.serial;
                /* Send delete to Controller */
                const payload = buildCommand(
                    { mqtt_id: pin.mqtt_id, serial: pin.serial, key_version: pin.key_version },
                    'delete_credential', { label: pin.label });
                publish(`adc100/${mqtt_id}/cmd`, JSON.stringify(payload));

                /* Mark as inactive in DB */
                await pool.query(
                    'UPDATE temp_pins SET active = FALSE WHERE id = $1',
                    [pin.id]
                );

                console.log(`Temp PIN expired and removed: ${pin.label} on ${mqtt_id}`);
            }

        } catch (err) {
            console.error('Monitor error:', err.message);
        }
    }, 60000);

    console.log('Device monitor started');
}

module.exports = startMonitor;