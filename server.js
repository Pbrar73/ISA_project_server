const bcrypt = require('bcrypt');
const express = require('express');
const path = require('path');
const mysql = require('mysql');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const url = require('url');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const app = express();
const port = process.env.PORT || 3019;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin: 'https://regal-axolotl-938764.netlify.app',
    credentials: true,
}));

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

let fetch;
import('node-fetch').then(({ default: nodeFetch }) => {
  fetch = nodeFetch;
});

const jwtSecretKey = 'new_secret_key_1118'; // Change this to a secure secret key

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });

    try {
        const decoded = jwt.verify(token, jwtSecretKey);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(400).json({ success: false, message: 'Invalid token.' });
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


app.post('/login', (req, res) => {
    const { email, password } = req.body;

    pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err) {
            res.status(500).send('Error finding user');
            return;
        }

        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err || !isMatch) {
                    res.status(401).json({ success: false, message: 'Incorrect email or password' });
                    return;
                }

                const token = jwt.sign({ id: user.id, email: user.email }, jwtSecretKey, { expiresIn: '5d' });

                res.cookie('token', token, {
                    httpOnly: true,
                    secure: true, 
                    sameSite: 'None', 
                    maxAge: 432000000
                });
                res.status(200).json({ success: true, message: 'Login successful' });
            });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    });
});


app.get('/check-session', verifyToken, (req, res) => {
    res.json({ success: true, message: "Session is valid." });
});

app.post('/generate-quote', verifyToken, async (req, res) => {
    const userEmail = req.user.email; 
    const inputs = req.body.inputs;

    if (!userEmail) {
        return res.status(400).json({ success: false, message: "User email is required." });
    }

    try {
        pool.query('SELECT * FROM users WHERE email = ?', [userEmail], async (err, results) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error finding user' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            const user = results[0];
            
            pool.query('UPDATE users SET api_calls_made = api_calls_made + 1 WHERE email = ?', [userEmail], async (updateErr) => {
                if (updateErr) {
                    console.error('Failed to increment API call count for user:', updateErr);
                }

                const response = await fetch(
                    'https://api-inference.huggingface.co/models/nandinib1999/quote-generator', {
                        headers: {
                            'Authorization': 'Bearer ' + process.env.HF_API_TOKEN,
                            'Content-Type': 'application/json'
                        },
                        method: 'POST',
                        body: JSON.stringify({ inputs })
                    }
                );

                if (!response.ok) {
                    throw new Error(`Error from Hugging Face API: ${response.statusText}`);
                }

                const data = await response.json();
                res.json(data);
            });
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Error fetching quote.');
    }
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});



app.get('/swagger.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'swagger.json'));
  });
  
 
  

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));