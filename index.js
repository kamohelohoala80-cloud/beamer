require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // PostgreSQL instead of MySQL

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// --- PostgreSQL connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.connect()
  .then(client => {
    console.log('✅ PostgreSQL Database connected successfully!');
    client.release();
  })
  .catch(err => {
    console.log('❌ PostgreSQL Database connection failed:', err.message);
  });

// --- JWT Middleware ---
function auth(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }
}

// --- AUTH ROUTES ---

// Register
app.post('/api/register', async (req, res) => {
  const { username, full_name, password, role, stream } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, full_name, password, role, stream) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [username, full_name, hash, role || 'student', stream || null]
    );
    res.json({ id: result.rows[0].id, message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password and role are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username=$1 AND role=$2', [username, role]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials or role mismatch' });
    }
    
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({
      id: user.id,
      username: user.username,
      role: user.role,
      stream: user.stream
    }, JWT_SECRET, { expiresIn: '1d' });

    res.json({
      token,
      role: user.role,
      full_name: user.full_name,
      user_id: user.id
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Test endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as current_time');
    res.json({ 
      message: 'Database connected successfully!',
      current_time: result.rows[0].current_time
    });
  } catch (err) {
    res.status(500).json({ error: 'Database connection failed', details: err.message });
  }
});

// Root route
app.get('/', (req, res) => {
  res.json({ message: 'LUCT Backend API is running!' });
});

// --- START SERVER ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));