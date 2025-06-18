// server.js - Your Node.js Authentication Server

require('dotenv').config(); // This will load variables from a .env file locally, but Railway uses its dashboard for env vars.
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based client for async/await
const app = express();
const port = process.env.PORT || 3000; // Railway often sets its own PORT env var, typically 3000

app.use(express.json()); // Middleware to parse JSON request bodies

// Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware to authenticate requests from the Roblox server
// This uses a shared secret key (SERVER_API_KEY)
app.use((req, res, next) => {
    const serverAuthKey = req.headers['x-server-auth'] || req.body.serverAuthKey;
    if (serverAuthKey === process.env.SERVER_API_KEY) {
        next(); // Authenticated, proceed to the route handler
    } else {
        console.warn('Unauthorized access attempt from:', req.ip, 'with key:', serverAuthKey);
        res.status(401).json({ success: false, message: 'Unauthorized: Invalid server key.' });
    }
});

// API Endpoint for Key/HWID Verification
app.post('/verify_key', async (req, res) => {
    const { key, hwid } = req.body;

    if (!key || !hwid) {
        return res.status(400).json({ success: false, message: 'Missing key or HWID.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.execute(
            'SELECT HWID, redeemedBy FROM whitelist WHERE `Key` = ?',
            [key]
        );

        if (rows.length === 0) {
            // Key not found in the database
            return res.status(200).json({ success: false, message: 'Invalid key.' });
        }

        const entry = rows[0];
        if (entry.HWID === null || entry.HWID === 'null' || entry.HWID === '') { // Also check for empty string
            // Key is found but HWID not set. Check if already redeemed.
            // 'redeemedBy' being 'true' or an actual ID indicates it was given out
            if (entry.redeemedBy !== null && entry.redeemedBy !== 'null' && entry.redeemedBy !== '') {
                return res.status(200).json({ success: false, message: 'This key has already been redeemed by another user.' });
            } else {
                // First time redemption: Associate HWID with this key
                await connection.execute(
                    'UPDATE whitelist SET HWID = ?, redeemedBy = ? WHERE `Key` = ?',
                    [hwid, 'true', key] // You could also store a Discord User ID here from your bot
                );
                return res.status(200).json({ success: true, message: 'Key redeemed successfully! Welcome.' });
            }
        } else if (entry.HWID === hwid) {
            // HWID matches, player is whitelisted
            return res.status(200).json({ success: true, message: 'Authentication successful! Welcome.' });
        } else {
            // HWID mismatch
            return res.status(200).json({ success: false, message: 'HWID mismatch. This key is linked to a different device.' });
        }
    } catch (error) {
        console.error('Database or server error during verification:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    } finally {
        if (connection) connection.release(); // Release the connection back to the pool
    }
});

// Basic health check endpoint (optional but good practice)
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Auth server is running.' });
});


app.listen(port, () => {
    console.log(`Auth server listening on port ${port}`);
});
