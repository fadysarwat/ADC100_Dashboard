const fs   = require('fs');
const path = require('path');
const pool = require('./pool');

/* Applied in order. Every file must be idempotent. */
const SCHEMA_FILES = ['schema.sql', 'rbac.sql'];

async function initDb() {
    for (const file of SCHEMA_FILES) {
        const sql = fs.readFileSync(path.join(__dirname, file), 'utf8');
        await pool.query(sql);
    }
    console.log('Database schema initialized');
}

module.exports = initDb;
