/* Replay / tamper test for protocol v2 (run by hand against ONE real device).
 *
 * Usage (from the dashboard folder, with .env that has the MQTT_* settings):
 *     node tests/replay_test.js <mqtt_id>
 *
 * Then press "Open" for that device in the dashboard ONCE.
 * The script captures that signed command and re-sends it:
 *     +3 s   unchanged copy          -> device must REJECT (nonce already used)
 *     +6 s   copy with ts changed    -> device must REJECT (invalid HMAC)
 *     +40 s  unchanged copy          -> device must REJECT (outside time window)
 * The door must open ONLY for the original command (the real click).
 * Watch the device serial log and the script output.
 */
require('dotenv').config();
const mqtt = require('mqtt');

const id = process.argv[2];
if (!id) { console.error('usage: node tests/replay_test.js <mqtt_id>'); process.exit(1); }
for (const k of ['MQTT_BROKER', 'MQTT_PORT', 'MQTT_USERNAME', 'MQTT_PASSWORD']) {
    if (!process.env[k]) { console.error('missing ' + k + ' in .env'); process.exit(1); }
}

const cmdTopic   = `adc100/${id}/cmd`;
const eventTopic = `adc100/${id}/event`;
let captured = null;
let sentByMe = 0;

const client = mqtt.connect(process.env.MQTT_BROKER, {
    port:     parseInt(process.env.MQTT_PORT),
    username: process.env.MQTT_USERNAME,
    password: process.env.MQTT_PASSWORD,
    protocol: 'mqtts',
});

function stamp() { return new Date().toISOString().slice(11, 19); }

function send(label, payload) {
    sentByMe++;
    console.log(`[${stamp()}] >>> ${label}`);
    client.publish(cmdTopic, payload, { qos: 1 });
}

client.on('connect', () => {
    console.log(`[${stamp()}] connected. Waiting for ONE signed command on ${cmdTopic} ...`);
    console.log('Now click "Open" for this device in the dashboard (once).');
    client.subscribe([cmdTopic, eventTopic]);
});

client.on('message', (topic, buf) => {
    const raw = buf.toString();
    if (topic === eventTopic) {
        console.log(`[${stamp()}] EVENT  ${raw}`);
        return;
    }
    if (sentByMe > 0 && captured) return;          /* ignore the echo of our own replays */
    if (captured) return;
    captured = raw;
    console.log(`[${stamp()}] captured command (${raw.length} bytes)`);

    setTimeout(() => send('REPLAY unchanged (expect reject: nonce used)', captured), 3000);

    setTimeout(() => {
        let obj;
        try { obj = JSON.parse(captured); } catch (e) { console.error('cannot parse captured command'); return; }
        obj.ts = (obj.ts || 0) + 1;
        send('TAMPERED ts+1 (expect reject: bad HMAC)', JSON.stringify(obj));
    }, 6000);

    setTimeout(() => send('REPLAY unchanged after 40 s (expect reject: outside time window)', captured), 40000);

    setTimeout(() => {
        console.log(`[${stamp()}] done. Check the device log: 3 rejections, and the door opened only once.`);
        client.end(false, () => process.exit(0));
    }, 50000);
});

client.on('error', (e) => {
    const parts = (e.errors && e.errors.length) ? e.errors : [e];
    for (const x of parts) {
        console.error('MQTT error:', x.code || '', x.message || '', x.address ? `${x.address}:${x.port}` : '');
    }
});
