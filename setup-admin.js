const bcrypt = require('bcrypt');
const pool   = require('./src/db/pool');
const initDb = require('./src/db/init');
require('dotenv').config();

async function setupAdmin() {
    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'adc100admin';

    /* Make sure role/org columns exist before inserting. */
    await initDb();

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
        `INSERT INTO users (username, password, role, org_id)
         VALUES ($1, $2, 'super_admin', NULL)
         ON CONFLICT (username) DO UPDATE
            SET password = $2, role = 'super_admin', org_id = NULL`,
        [username, hash]
    );

    console.log(`Super admin ready: ${username}`);
    process.exit(0);
}

setupAdmin().catch(err => {
    console.error(err);
    process.exit(1);
});
