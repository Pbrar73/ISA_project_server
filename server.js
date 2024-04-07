const bcrypt = require('bcrypt');
const express = require('express');
const path = require('path');
const mysql = require('mysql');
const cookieParser = require('cookie-parser');
const url = require('url');

const app = express();
const port = process.env.PORT || 3019;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'https://regal-axolotl-938764.netlify.app');
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


let fetch;
import('node-fetch').then(({ default: nodeFetch }) => {
  fetch = nodeFetch;
});

const verifySession = (req, res, next) => {
    const sessionId = req.cookies.sessionId;

    if (!sessionId) {
        return res.status(401).json({ success: false, message: "Access Denied: Session ID is not provided or is invalid." });
    }
    next();
};

app.get('/check-session', verifySession, (req, res) => {
    res.json({ success: true, message: "Session is valid." });
});

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
                    res.cookie('sessionId', user.id, { httpOnly: true });
                    res.status(200).json({ success: true, message: 'Login successful' });
                } else {
                    res.status(401).json({ success: false, message: 'Incorrect password' });
                }
            });
        }
    });
});


// Endpoint to get the number of API calls made by a user
app.get('/api-calls-count', (req, res) => {
    // Extract the user's email from query parameters
    const userEmail = req.query.email;

    if (!userEmail) {
        return res.status(400).json({ success: false, message: "User email is required." });
    }

    // Query the database for the user's api_calls_made
    pool.query('SELECT api_calls_made FROM users WHERE email = ?', [userEmail], (err, results) => {
        if (err) {
            console.error('Error fetching user API call count:', err);
            return res.status(500).json({ success: false, message: 'Error fetching API call count' });
        }

        if (results.length > 0) {
            // Send back the number of API calls made
            const apiCallsMade = results[0].api_calls_made;
            res.json({ success: true, apiCallsMade });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    });
});


app.post('/generate-quote', async (req, res) => {
    const userEmail = req.body.userEmail; // Assuming the client sends userEmail
    const inputs = req.body.inputs;

    if (!userEmail) {
        return res.status(400).json({ success: false, message: "User email is required." });
    }

    try {
        // First, find the user by email and increment their api_calls_made
        pool.query('SELECT * FROM users WHERE email = ?', [userEmail], async (err, results) => {
            if (err) {
                return res.status(500).json({ success: false, message: 'Error finding user' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            const user = results[0];
            
            // Increment api_calls_made
            pool.query('UPDATE users SET api_calls_made = api_calls_made + 1 WHERE email = ?', [userEmail], async (updateErr) => {
                if (updateErr) {
                    // Log error, but don't necessarily fail the whole operation
                    console.error('Failed to increment API call count for user:', updateErr);
                }

                // Proceed to fetch the quote as before
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
    console.log(`Server running on http://localhost:${port}`);
});