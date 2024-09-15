const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.use(express.static('public'));
app.use(bodyParser.json());

const PORT = 3000;
const SECRET_KEY = 'your_secret_key';

let db;

async function initializeDatabase() {
    try {
        db = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: '*********',
            database: 'learning_platform'
        });
        console.log('MySQL Database connected successfully.');
    } catch (error) {
        console.error('Error connecting to the MySQL database:', error);
        process.exit(1);
    }
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Registration Route
app.post('/register', async (req, res) => {
    const { username, password, email, mobile } = req.body;

    try {
        const [existingUser] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (existingUser.length > 0) {
            return res.json({ message: 'Username already exists!' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        await db.execute('INSERT INTO users (username, password_hash, email, mobile) VALUES (?, ?, ?, ?)', [username, passwordHash, email, mobile]);

        res.json({ message: 'Registration successful!' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.json({ message: 'Error during registration!' });
    }
});

// Login Route with Blocking Mechanism
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.json({ message: 'Invalid username or password!' });
        }

        const user = users[0];

        if (user.blocked_until && new Date(user.blocked_until) > new Date()) {
            return res.json({ message: 'Account is blocked. Try after 24 hours.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            await db.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', [user.id]);

            if (user.failed_attempts + 1 >= 3) {
                await db.execute('UPDATE users SET blocked_until = DATE_ADD(NOW(), INTERVAL 24 HOUR) WHERE id = ?', [user.id]);
                return res.json({ message: 'Account blocked due to multiple failed login attempts. Please try again after 24 hours.' });
            }

            return res.json({ message: 'Invalid username or password!' });
        }

        await db.execute('UPDATE users SET failed_attempts = 0, blocked_until = NULL WHERE id = ?', [user.id]);

        const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

        res.json({ message: 'Login successful!', token });
    } catch (error) {
        console.error('Error during login:', error);
        res.json({ message: 'Error during login!' });
    }
});

// Start the Server and Initialize the Database
app.listen(PORT, async () => {
    await initializeDatabase();
    console.log(`Server running on http://localhost:${PORT}`);
});
