// server.js - Your Node.js Authentication Server

// Load environment variables. IMPORTANT: Railway reads these from its dashboard,
// but 'dotenv' is useful for local testing.
require('dotenv').config(); 
const express = require('express');
const mysql = require('mysql2/promise'); // Using promise-based client for async/await
const app = express();
// Railway typically sets its own PORT environment variable (e.g., 8080 or 3000)
const port = process.env.PORT || 3000; 

app.use(express.json()); // Middleware to parse JSON request bodies

// --- Database Connection Pool ---
// These credentials come from Railway's environment variables (or your .env for local testing)
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10, // Max number of concurrent connections
    queueLimit: 0        // Unlimited queue for connections
});

// --- Middleware to Authenticate Requests from Your Executor Script ---
// This uses a shared secret key (SERVER_API_KEY)
app.use((req, res, next) => {
    // Expect the key in the 'x-server-auth' header or in the request body
    const serverAuthKey = req.headers['x-server-auth'] || req.body.serverAuthKey; 

    if (serverAuthKey === process.env.SERVER_API_KEY) {
        next(); // Authenticated, proceed to the next route handler
    } else {
        console.warn(`Unauthorized access attempt from: ${req.ip} with key: ${serverAuthKey}`);
        res.status(401).json({ success: false, message: 'Unauthorized: Invalid server key.' });
    }
});

// --- API Endpoint for Key/HWID Verification ---
// This endpoint receives the key and HWID from the executor
app.post('/verify_key', async (req, res) => {
    const { key, hwid } = req.body; // Destructure key and hwid from the request body

    if (!key || !hwid) {
        return res.status(400).json({ success: false, message: 'Missing key or HWID.' });
    }

    let connection; // Declare connection outside try to ensure it's accessible in finally
    try {
        connection = await pool.getConnection(); // Get a connection from the pool
        const [rows] = await connection.execute(
            'SELECT HWID, redeemedBy FROM whitelist WHERE `Key` = ?',
            [key]
        );

        if (rows.length === 0) {
            // Key not found in the database
            return res.status(200).json({ success: false, message: 'Invalid key.' });
        }

        const entry = rows[0]; // Get the first (and should be only) matching entry

        // Case 1: Key is found, but HWID is not yet set (first time redemption)
        if (entry.HWID === null || entry.HWID === 'null' || entry.HWID === '') {
            // Check if it's already marked as redeemed by another user via 'redeemedBy' column
            if (entry.redeemedBy !== null && entry.redeemedBy !== 'null' && entry.redeemedBy !== '') {
                return res.status(200).json({ success: false, message: 'This key has already been redeemed by another user.' });
            } else {
                // First time use of this key: Link the current HWID to it
                await connection.execute(
                    'UPDATE whitelist SET HWID = ?, redeemedBy = ? WHERE `Key` = ?',
                    [hwid, 'true', key] // 'true' or a specific user ID (e.g., Discord ID)
                );
                return res.status(200).json({ success: true, message: 'Key redeemed successfully! Welcome.' });
            }
        } 
        // Case 2: Key is found, and HWID is already set
        else if (entry.HWID === hwid) {
            // HWID matches the one on record, so the user is authorized
            return res.status(200).json({ success: true, message: 'Authentication successful! Welcome.' });
        } 
        // Case 3: Key is found, but HWID does not match
        else {
            return res.status(200).json({ success: false, message: 'HWID mismatch. This key is linked to a different device.' });
        }
    } catch (error) {
        console.error('Database or server error during verification:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    } finally {
        if (connection) connection.release(); // IMPORTANT: Release the connection back to the pool
    }
});

// --- Basic Health Check Endpoint ---
// Useful for checking if your server is alive (e.g., via friendly-upliftment-production.up.railway.app/health)
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Auth server is running.' });
});

// --- Start the Server ---
app.listen(port, () => {
    console.log(`Auth server listening on port ${port}`);
});
