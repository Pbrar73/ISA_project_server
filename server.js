const bcrypt = require('bcrypt');
const express = require('express');
const path = require('path');
const mysql = require('mysql');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken'); // Added JWT library
const url = require('url');

const app = express();
const port = process.env.PORT || 3019
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'https://660e9b7b6b4264051b1ed93c--regal-axolotl-938764.netlify.app');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

const dbUrl = process.env.JAWSDB_URL;
let dbOptions = {};

if (dbUrl) {
    const parsedUrl = new url.URL(dbUrl);
    dbOptions = {
        host: parsedUrl.hostname,
        user: parsedUrl.username,
        password: parsedUrl.password,
        database: parsedUrl.pathname.substr(1),
        port: parsedUrl.port,
        connectionLimit: 10
    };
} else {
    dbOptions = {
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'termproject_4537',
        connectionLimit: 10
    };
}

const pool = mysql.createPool(dbOptions);

const createUsersTable = () => {
    const sql = `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        api_calls_made INT DEFAULT 0,
        is_admin BOOLEAN DEFAULT FALSE
    )`;
    pool.query(sql, error => {
        if (error) throw error;
        console.log('Users table ensured');
    });
};

createUsersTable();

const verifyToken = (req, res, next) => {
    const token = req.cookies.sessionId;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access Denied: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, 'your_secret_key_here');
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(403).json({ success: false, message: 'Invalid token' });
    }
};

app.post('/register', (req, res) => {
    const { email, password } = req.body;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            res.status(500).send('Error hashing password');
            return;
        }

        const user = { email, password: hashedPassword };

        pool.query('INSERT INTO users SET ?', user, (err, result) => {
            if (err) {
                res.status(500).json({ success: false, message: 'Error registering user' });
                return;
            }
            console.log('User registered');
            res.status(200).json({ success: true, message: 'User registered' });
        });
    });
});

app.post('/index', (req, res) => {
    const { email, password } = req.body;

    pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            res.status(500).send('Error finding user');
            return;
        }

        if (results.length > 0) {
            const user = results[0];
            const hashedPassword = user.password;

            bcrypt.compare(password, hashedPassword, (err, isMatch) => {
                if (err) {
                    res.status(500).json({ success: false, message: 'Error comparing passwords' });
                    return;
                }
                if (isMatch) {
                    // Generate JWT token
                    const token = jwt.sign({ userId: user.id }, 'your_secret_key_here', { expiresIn: '1h' });
                    
                    // Set JWT token as HTTP-only cookie
                    res.cookie('sessionId', token, { httpOnly: true, maxAge: 3600000 });
                    res.status(200).json({ success: true, message: 'Login successful' });
                } else {
                    res.status(401).json({ success: false, message: 'Incorrect password' });
                }
            });
        }
    });
});

app.get('/check-session', verifyToken, (req, res) => {
    res.json({ success: true, message: 'Session is valid' });
});

app.post('/generate-quote', async (req, res) => {
    try {
        const response = await fetch(
            'https://api-inference.huggingface.co/models/nandinib1999/quote-generator', {
                headers: {
                    'Authorization': 'Bearer ' + process.env.HF_API_TOKEN,
                    'Content-Type': 'application/json'
                },
                method: 'POST',
                body: JSON.stringify({ inputs: req.body.inputs })
            }
        );

        if (!response.ok) {
            throw new Error(`Error from Hugging Face API: ${response.statusText}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Error fetching quote.');
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
