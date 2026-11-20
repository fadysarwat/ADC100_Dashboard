/* ============================================================
   Device command signing.  One place, so no route ever signs by hand.

   Protocol v2 (per-device key, field-bound, nonce): see
   docs/PROTOCOL_V2.md in the ADC_100_Controller repository
   (branch "production"). Both sides must stay byte-identical;
   tests/vectors_v2.json is generated from this file and verified by a
   C host test of the real firmware code.

   Protocol v1 (legacy shared secret) is kept ONLY for devices that have not
   been migrated yet (devices.key_version = 1).
   ============================================================ */
const crypto = require('crypto');

/* Signed fields per command — identical to the firmware table (sig_v2.c). */
const FIELDS = {
    open:              [['relay_mode', 's'], ['relay_duration', 'n']],
    set_schedule:      [['enabled', 's'], ['start', 's'], ['end', 's']],
    add_credential:    [['cred_type', 's'], ['cred_data', 's'], ['label', 's'], ['duress', 's']],
    delete_credential: [['label', 's']],
    clear_credentials: [],
    set_touch:         [['enabled', 's']],
    set_wifi:          [['ssid', 's'], ['pass', 's']],
    apply_wifi:        [],
    reset_wifi:        [],
    restart:           [],
    get_status:        [],
    get_logs:          [],
    clear_logs:        [],
    ota_update:        [['url', 's']],
    set_ble_name:      [['name', 's']]
};

const KEY_LABEL = 'adc100-device-key-v1\n';
const BLE_LABEL = 'adc100-ble-key-v1';

function hmacHex(key, msg) {
    return crypto.createHmac('sha256', key).update(msg).digest('hex');
}

function masterKey() {
    const m = process.env.DEVICE_MASTER_KEY;
    if (!m || m.length < 32) {
        const err = new Error('DEVICE_MASTER_KEY is not set (min 32 chars). It is required for v2 devices.');
        err.code = 'NO_MASTER_KEY';
        throw err;
    }
    return m;
}

function deviceId(device) {
    return device.mqtt_id || device.serial;
}

/* device_key = HMAC(MASTER, "adc100-device-key-v1\n" + device_id) -> Buffer(32) */
function deviceKey(device) {
    return crypto.createHmac('sha256', masterKey()).update(KEY_LABEL + deviceId(device)).digest();
}

/* ble_key = HMAC(device_key, "adc100-ble-key-v1") -> Buffer(32) */
function bleKey(device) {
    return crypto.createHmac('sha256', deviceKey(device)).update(BLE_LABEL).digest();
}

function fieldText(kind, value) {
    if (value === undefined || value === null) return '';
    if (kind === 'n') {
        const n = Number(value);
        return Number.isFinite(n) ? String(Math.trunc(n) >>> 0) : '';
    }
    /* The firmware JSON reader returns the raw JSON text of a string with only
       \" turned back into ". Sign exactly what the device will see, so values
       with backslashes, newlines or quotes verify correctly. */
    return JSON.stringify(String(value)).slice(1, -1).replace(/\\"/g, '"');
}

/* The exact bytes that are signed (exported for the conformance vectors). */
function v2Message(id, cmd, ts, nonce, fields) {
    let msg = `v2\n${id}\n${cmd}\n${ts}\n${nonce}\n`;
    for (const [name, kind] of FIELDS[cmd]) {
        const v = fieldText(kind, fields[name]);
        msg += `${Buffer.byteLength(v, 'utf8')}:${v}\n`;
    }
    return msg;
}

/* Build the JSON object to publish to adc100/<id>/cmd.
   fields: values of the command (strings for string fields). */
function buildCommand(device, cmd, fields = {}, opts = {}) {
    const ts = opts.ts !== undefined ? opts.ts : Math.floor(Date.now() / 1000);

    if ((device.key_version || 1) >= 2) {
        if (!FIELDS[cmd]) throw new Error(`unknown command ${cmd}`);
        const nonce = opts.nonce || crypto.randomBytes(8).toString('hex');
        const payload = { cmd };
        for (const [name, kind] of FIELDS[cmd]) {
            if (fields[name] === undefined || fields[name] === null) continue;
            payload[name] = kind === 'n' ? Number(fields[name]) : String(fields[name]);
        }
        payload.ts = ts;
        payload.v = 2;
        payload.n = nonce;
        payload.hmac = hmacHex(deviceKey(device), v2Message(deviceId(device), cmd, ts, nonce, fields));
        return payload;
    }

    /* legacy v1: shared secret, signature over "cmd:ts" only */
    const secret = process.env.MQTT_SECRET;
    if (!secret) throw new Error('MQTT_SECRET is not set (needed for legacy devices)');
    const payload = { cmd, ...fields };
    /* the legacy firmware reads "pass"; older dashboard builds sent "password" */
    if (cmd === 'set_wifi' && payload.pass === undefined && payload.password !== undefined) payload.pass = payload.password;
    payload.ts = ts;
    payload.hmac = hmacHex(secret, `${cmd}:${ts}`);
    return payload;
}

/* Temporary QR for ONE device (v2 only). Returns the exact text to encode.
   The reader hands the door at most 112 bytes, so the QR is kept short (~85 bytes):
   the door id is not inside (the door verifies with its OWN id, so a QR made for
   another door fails) and the MAC is the first 128 bits of the HMAC-SHA256. */
const QR_MAC_HEX = 32;
function temporaryQr(device, iat, exp) {
    const id = deviceId(device);
    const hmac = hmacHex(deviceKey(device), `v2tqr\n${id}\n${iat}\n${exp}`).slice(0, QR_MAC_HEX);
    return JSON.stringify({ v: 2, iat, exp, hmac });
}

/* Everything needed to provision a device (NVS namespace adc_sec). */
function provisionBundle(device, mqtt = {}) {
    const id = deviceId(device);
    const keyHex = deviceKey(device).toString('hex');
    const rows = [
        'key,type,encoding,value',
        'adc_sec,namespace,,',
        `dev_key,data,hex2bin,${keyHex}`,
        'legacy_off,data,u8,1'
    ];
    if (mqtt.uri)  rows.push(`mqtt_uri,data,string,${mqtt.uri}`);
    if (mqtt.user) rows.push(`mqtt_user,data,string,${mqtt.user}`);
    if (mqtt.pass) rows.push(`mqtt_pass,data,string,${mqtt.pass}`);
    return { device_id: id, key_hex: keyHex, nvs_csv: rows.join('\n') + '\n' };
}

/* One-time migration command for a deployed device still on v1. */
function buildProvisionCommand(device) {
    const secret = process.env.MQTT_SECRET;
    if (!secret) throw new Error('MQTT_SECRET is not set (needed to migrate a legacy device)');
    const ts = Math.floor(Date.now() / 1000);
    return {
        cmd: 'provision_v2',
        dev_key: deviceKey(device).toString('hex'),
        ts,
        hmac: hmacHex(secret, `provision_v2:${ts}`)
    };
}

module.exports = {
    FIELDS, QR_MAC_HEX, deviceKey, bleKey, v2Message, buildCommand, temporaryQr,
    provisionBundle, buildProvisionCommand, deviceId
};
