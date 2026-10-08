const bcrypt = require('bcrypt');
const pool   = require('./src/db/pool');
require('dotenv').config();

async function setupAdmin() {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'adc100admin';

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
        `INSERT INTO users (username, password)
         VALUES ($1, $2)
         ON CONFLICT (username) DO UPDATE SET password = $2`,
        [username, hash]
    );

    console.log(`Admin user created: ${username}`);
    process.exit(0);
}

setupAdmin().catch(err => {
    console.error(err);
    process.exit(1);
});