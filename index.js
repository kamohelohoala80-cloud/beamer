require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const ExcelJS = require('exceljs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

// --- MySQL connection pool ---
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '123456',
  database: process.env.DB_NAME || 'luct_reporting_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Debug database config
console.log('🔧 Database config:', {
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'luct_reporting_system'
});

// Test database connection on startup
pool.getConnection()
  .then(connection => {
    console.log('✅ MySQL Database connected successfully!');
    connection.release();
  })
  .catch(err => {
    console.log('❌ MySQL Database connection failed:', err.message);
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
  console.log('📝 Register attempt:', username);
  
  try {
    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, full_name, password, role, stream) VALUES (?,?,?,?,?)',
      [username, full_name, hash, role || 'student', stream || null]
    );
    console.log('✅ User registered:', username);
    res.json({ id: result.insertId, message: 'User registered successfully' });
  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Login - UPDATED VERSION WITH ROLE CHECK
app.post('/api/login', async (req, res) => {
  const { username, password, role } = req.body;
  console.log('🔐 Login attempt - Username:', username, 'Role:', role, 'Password length:', password?.length);

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password and role are required' });
  }

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username=? AND role=?', [username, role]);
    console.log('👤 User found with matching role:', rows.length > 0, 'Username:', username, 'Requested role:', role);
    
    if (rows.length === 0) {
      console.log('❌ No user found with username:', username, 'and role:', role);
      return res.status(400).json({ error: 'Invalid credentials or role mismatch' });
    }
    
    const user = rows[0];
    console.log('🔑 Comparing password for user:', user.username, 'Actual role:', user.role);

    const match = await bcrypt.compare(password, user.password);
    console.log('✅ Password match result:', match);
    
    if (!match) {
      console.log('❌ Password does not match for user:', username);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({
      id: user.id,
      username: user.username,
      role: user.role,
      full_name: user.full_name,
      stream: user.stream
    }, JWT_SECRET, { expiresIn: '1d' });

    console.log('🎉 Login successful for user:', username, 'as role:', user.role);
    res.json({
      token,
      role: user.role,
      full_name: user.full_name,
      user_id: user.id
    });
  } catch (err) {
    console.error('❌ Login error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- FACULTIES ---
app.get('/api/faculties', auth(), async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM faculties ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- COURSES ---
app.get('/api/courses', auth(), async (req, res) => {
  const { faculty_id, q } = req.query;
  let sql = `
    SELECT c.*, f.name as faculty_name, u.full_name as lecturer_name
    FROM courses c
    LEFT JOIN faculties f ON c.faculty_id = f.id
    LEFT JOIN users u ON c.lecturer_id = u.id
    WHERE 1=1
  `;
  const params = [];

  if (faculty_id) {
    sql += ' AND c.faculty_id=?';
    params.push(faculty_id);
  }
  if (q) {
    sql += ' AND (c.name LIKE ? OR c.code LIKE ?)';
    params.push(`%${q}%`, `%${q}%`);
  }

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// PL adds a course
app.post('/api/courses', auth('pl'), async (req, res) => {
  const { faculty_id, name, code, stream } = req.body;
  try {
    const [result] = await pool.execute(
      'INSERT INTO courses (faculty_id, name, code, stream) VALUES (?,?,?,?)',
      [faculty_id, name, code, stream]
    );
    res.json({ id: result.insertId, message: 'Course created successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// PL assigns lecturer to course
app.put('/api/courses/:id', auth('pl'), async (req, res) => {
  const { lecturer_id } = req.body;
  try {
    await pool.execute('UPDATE courses SET lecturer_id = ? WHERE id = ?', [lecturer_id, req.params.id]);
    res.json({ message: 'Lecturer assigned successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- CLASSES ---
app.get('/api/classes', auth(), async (req, res) => {
  const { course_id } = req.query;
  let sql = `
    SELECT c.*, co.name as course_name, co.code as course_code
    FROM classes c
    LEFT JOIN courses co ON c.course_id = co.id
    WHERE 1=1
  `;
  const params = [];

  if (course_id) {
    sql += ' AND c.course_id=?';
    params.push(course_id);
  }

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- USERS BY ROLE ---
app.get('/api/users', auth(), async (req, res) => {
  const { role } = req.query;
  let sql = 'SELECT id, username, full_name, role, stream FROM users WHERE 1=1';
  const params = [];

  if (role) {
    sql += ' AND role=?';
    params.push(role);
  }

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- LECTURE REPORTS ---

// Submit report (Lecturer)
app.post('/api/reports', auth('lecturer'), async (req, res) => {
  const {
    faculty_id, course_id, class_id, lecturer_name, week_of_reporting,
    lecture_date, topic_taught, learning_outcomes, recommendations,
    actual_students_present, venue, scheduled_time
  } = req.body;

  try {
    const [result] = await pool.execute(
      `INSERT INTO reports
      (faculty_id, course_id, class_id, lecturer_id, lecturer_name, week_of_reporting,
       lecture_date, topic_taught, learning_outcomes, recommendations,
       actual_students_present, venue, scheduled_time)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        faculty_id, course_id, class_id, req.user.id, lecturer_name,
        week_of_reporting, lecture_date, topic_taught, learning_outcomes,
        recommendations, actual_students_present, venue, scheduled_time
      ]
    );
    res.json({ id: result.insertId, message: 'Report submitted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get reports with filtering
app.get('/api/reports', auth(), async (req, res) => {
  const { q } = req.query;
  let sql = `
    SELECT r.*, c.name AS course_name, c.code AS course_code,
           f.name AS faculty_name, cl.name AS class_name
    FROM reports r
    LEFT JOIN courses c ON r.course_id = c.id
    LEFT JOIN faculties f ON r.faculty_id = f.id
    LEFT JOIN classes cl ON r.class_id = cl.id
    WHERE 1=1
  `;
  const params = [];

  // Role-based filtering
  if (req.user.role === 'lecturer') {
    sql += ' AND r.lecturer_id = ?';
    params.push(req.user.id);
  }

  // Search filter
  if (q) {
    sql += ' AND (c.name LIKE ? OR r.lecturer_name LIKE ? OR r.topic_taught LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  sql += ' ORDER BY r.created_at DESC';

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get student reports
app.get('/api/student/reports', auth('student'), async (req, res) => {
  const { q } = req.query;
  let sql = 'SELECT * FROM student_reports WHERE 1=1';
  const params = [];

  if (q) {
    sql += ' AND (course_name LIKE ? OR lecturer_name LIKE ? OR topic_taught LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  sql += ' ORDER BY lecture_date DESC';

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get lecturer classes
app.get('/api/lecturer/classes', auth('lecturer'), async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM lecturer_classes');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Submit PRL feedback
app.post('/api/reports/:id/feedback', auth('prl'), async (req, res) => {
  const { feedback } = req.body;
  try {
    await pool.execute(
      'UPDATE reports SET prl_feedback = ? WHERE id = ?',
      [feedback, req.params.id]
    );
    res.json({ message: 'Feedback submitted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- RATINGS ---
app.post('/api/ratings', auth(), async (req, res) => {
  const { target_id, target_type, rating, comment } = req.body;
  try {
    const [result] = await pool.execute(
      'INSERT INTO ratings (target_id, target_type, rating, comment, created_by) VALUES (?,?,?,?,?)',
      [target_id, target_type, rating, comment, req.user.id]
    );
    res.json({ id: result.insertId, message: 'Rating submitted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/ratings', auth(), async (req, res) => {
  const { target_id, target_type } = req.query;
  let sql = `
    SELECT r.*, u.full_name AS user_name
    FROM ratings r
    LEFT JOIN users u ON r.created_by = u.id
    WHERE 1=1
  `;
  const params = [];

  if (target_id) {
    sql += ' AND r.target_id = ?';
    params.push(target_id);
  }
  if (target_type) {
    sql += ' AND r.target_type = ?';
    params.push(target_type);
  }

  try {
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- EXPORT REPORTS TO EXCEL ---
app.get('/api/reports/export', auth(), async (req, res) => {
  const { q } = req.query;
  let sql = `
    SELECT r.*, c.name AS course_name, c.code AS course_code,
           f.name AS faculty_name, cl.name AS class_name
    FROM reports r
    LEFT JOIN courses c ON r.course_id = c.id
    LEFT JOIN faculties f ON r.faculty_id = f.id
    LEFT JOIN classes cl ON r.class_id = cl.id
    WHERE 1=1
  `;
  const params = [];

  if (req.user.role === 'lecturer') {
    sql += ' AND r.lecturer_id = ?';
    params.push(req.user.id);
  }

  if (q) {
    sql += ' AND (c.name LIKE ? OR r.lecturer_name LIKE ? OR r.topic_taught LIKE ?)';
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  sql += ' ORDER BY r.created_at DESC';

  try {
    const [rows] = await pool.execute(sql, params);
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Reports');

    if (rows.length > 0) {
      const headers = Object.keys(rows[0]);
      worksheet.addRow(headers);
      rows.forEach(row => worksheet.addRow(headers.map(h => row[h] || '')));
    }

    res.setHeader('Content-Disposition', 'attachment; filename=reports.xlsx');
    res.set('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    await workbook.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Database error' });
  }
});

// --- TEST ENDPOINT ---
app.get('/api/test-db', async (req, res) => {
  try {
    const [users] = await pool.execute('SELECT * FROM users');
    const [reports] = await pool.execute('SELECT * FROM reports');
    res.json({
      message: 'Database connected successfully!',
      users_count: users.length,
      reports_count: reports.length
    });
  } catch (err) {
    console.error('Database connection error:', err);
    res.status(500).json({ error: 'Database connection failed', details: err.message });
  }
});

// Add root route
app.get('/', (req, res) => {
  res.json({ message: 'LUCT Backend API is running!' });
});

// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));