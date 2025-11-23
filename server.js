// @ts-nocheck
// server.js - ENVIROTRACK (cleaned & Render-ready)

require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const PORT = process.env.PORT || 3000;

// Basic safety: require a JWT secret (fallback only for local/dev)
if (!process.env.JWT_SECRET) {
  console.warn('⚠️  Warning: JWT_SECRET is not set. Tokens will be signed with a fallback secret (not secure). Set JWT_SECRET in env on production.');
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'dev_fallback_change_me';
}

// Initialize Gemini AI (will be "configured" or "missing" depending on env)
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ========== HELPERS ==========

function validateAndParseGPS(latString, lngString) {
  const lat = parseFloat(latString);
  const lng = parseFloat(lngString);

  if (isNaN(lat) || isNaN(lng)) {
    return {
      valid: false,
      error: 'GPS coordinates must be valid numbers. Received: lat=' + latString + ', lng=' + lngString
    };
  }
  if (lat < -90 || lat > 90) {
    return { valid: false, error: 'Latitude must be between -90 and 90. Got: ' + lat };
  }
  if (lng < -180 || lng > 180) {
    return { valid: false, error: 'Longitude must be between -180 and 180. Got: ' + lng };
  }
  return { valid: true, latitude: lat, longitude: lng };
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp'
  };
  return mimeTypes[ext] || 'image/jpeg';
}

// Convert stored image_url (may start with "/") into a local filesystem path
function localImagePathFromUrl(imageUrl) {
  if (!imageUrl) return null;
  // remove leading slashes to avoid path.join ignoring __dirname
  const cleaned = imageUrl.replace(/^\/+/, '');
  return path.join(__dirname, cleaned);
}

// ========== AI FUNCTIONS ==========

async function analyzeImageForWaste(filePath) {
  const startTime = Date.now();
  try {
    const model = genAI.getGenerativeModel({
      model: "gemini-2.0-flash",
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 100,
        topP: 0.9,
      }
    });

    const imageData = fs.readFileSync(filePath);
    const base64Image = imageData.toString('base64');

    const imagePart = {
      inlineData: {
        data: base64Image,
        mimeType: getMimeType(filePath)
      }
    };

    const prompt = 'Look at this image carefully. Does it contain any visible waste/garbage/trash/litter? Answer ONLY with "Yes" or "No".';
    const result = await model.generateContent([prompt, imagePart]);
    const response = await result.response;
    const text = (await response.text()).trim();
    const normalized = text.toLowerCase();

    const isWaste = normalized.includes('yes');

    return {
      isWaste,
      text,
      confidence: isWaste ? 'high' : 'low',
      elapsed: Date.now() - startTime
    };
  } catch (err) {
    return {
      isWaste: true,
      text: 'AI unavailable: ' + (err && err.message ? err.message : 'unknown'),
      confidence: 'unknown',
      elapsed: Date.now() - startTime
    };
  }
}

async function verifyCleanup(beforeImagePath, afterImagePath) {
  const startTime = Date.now();
  try {
    const model = genAI.getGenerativeModel({
      model: "gemini-2.0-flash-exp",
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 250
      }
    });

    if (!fs.existsSync(beforeImagePath)) throw new Error('Before image not found: ' + beforeImagePath);
    if (!fs.existsSync(afterImagePath)) throw new Error('After image not found: ' + afterImagePath);

    const beforeData = fs.readFileSync(beforeImagePath);
    const afterData = fs.readFileSync(afterImagePath);

    const beforeImage = { inlineData: { data: beforeData.toString('base64'), mimeType: getMimeType(beforeImagePath) } };
    const afterImage = { inlineData: { data: afterData.toString('base64'), mimeType: getMimeType(afterImagePath) } };

    const prompt = `Compare two images (before/after cleanup). Respond ONLY:
Cleaned: Yes/No
Similar Images: Yes/No
Confidence: High/Medium/Low`;

    const result = await model.generateContent([prompt, beforeImage, afterImage]);
    const response = await result.response;
    const text = (await response.text()).trim();
    const normalized = text.toLowerCase();

    const isCleaned = normalized.includes('cleaned: yes') || (normalized.includes('cleaned') && normalized.includes('yes'));
    const similarImages = normalized.includes('similar images: yes') || normalized.includes('similar: yes');
    const confidence = normalized.includes('high') ? 'high' : (normalized.includes('medium') ? 'medium' : 'low');

    return {
      verified: isCleaned && similarImages,
      aiResponse: text,
      confidence,
      similarImages,
      elapsed: Date.now() - startTime
    };
  } catch (err) {
    return {
      verified: false,
      aiResponse: 'Verification failed: ' + (err && err.message ? err.message : 'unknown'),
      confidence: 'unknown',
      similarImages: false,
      elapsed: Date.now() - startTime
    };
  }
}

// ========== DATABASE (Render friendly SSL) ==========
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT, 10) : 5432,
  ssl: {
    rejectUnauthorized: false
  }
});

// Auto-create tables
const createTablesIfNotExist = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS waste_reports (
        id SERIAL PRIMARY KEY,
        latitude DECIMAL(10,8) NOT NULL,
        longitude DECIMAL(11,8) NOT NULL,
        description TEXT,
        image_url VARCHAR(500) NOT NULL,
        reported_by VARCHAR(255),
        reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_cleaned BOOLEAN DEFAULT FALSE,
        cleaned_by_user_id INTEGER REFERENCES users(id),
        cleaned_image_url VARCHAR(500),
        cleaned_at TIMESTAMP,
        points INTEGER DEFAULT 10,
        cleanup_verified BOOLEAN DEFAULT FALSE,
        verification_confidence VARCHAR(20),
        ai_comparison_result TEXT
      );
    `);
    console.log('✅ Database tables checked/created successfully');
  } catch (err) {
    console.error('❌ Error creating tables:', err);
  }
};

createTablesIfNotExist();

// quick connection test
pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ Database connection error:', err.stack || err);
    return;
  }
  client.query('SELECT NOW()', (err, result) => {
    release();
    if (err) {
      console.error('❌ Query error:', err.stack || err);
      return;
    }
    console.log('✅ Connected to PostgreSQL:', result.rows[0].now);
  });
});

// ========== MIDDLEWARE & STATIC ==========

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname, 'public')));

// multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname))
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  if (mimetype && extname) return cb(null, true);
  cb(new Error('Only images allowed'));
};

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter
});

// auth middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ========== API ROUTES ==========

// 1. Register
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashedPassword, role || 'user']
    );
    res.status(201).json({ message: 'User registered', user: result.rows[0] });
  } catch (err) {
    if (err && err.code === '23505') return res.status(409).json({ message: 'Username exists' });
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 2. Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const accessToken = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful', accessToken, role: user.role, username: user.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 3. Report Waste (with image)
app.post('/api/report-waste', upload.single('wasteImage'), async (req, res) => {
  const { latitude, longitude, description, reportedBy } = req.body;
  if (!req.file) return res.status(400).json({ message: 'Image required' });

  const gps = validateAndParseGPS(latitude, longitude);
  if (!gps.valid) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(400).json({ message: gps.error });
  }

  try {
    const analysisResult = await analyzeImageForWaste(req.file.path);
    if (!analysisResult.isWaste) {
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(400).json({
        message: 'AI did not detect waste in this image.',
        aiAnalysis: { result: analysisResult.text, confidence: analysisResult.confidence, processingTime: analysisResult.elapsed + 'ms' }
      });
    }

    const imageUrl = '/uploads/' + req.file.filename;
    const q = 'INSERT INTO waste_reports (latitude, longitude, description, image_url, reported_by) VALUES ($1,$2,$3,$4,$5) RETURNING *';
    const values = [gps.latitude, gps.longitude, description || null, imageUrl, reportedBy || 'Anonymous'];
    const result = await pool.query(q, values);

    res.status(201).json({
      message: 'Waste report submitted successfully!',
      report: result.rows[0],
      aiAnalysis: { result: analysisResult.text, confidence: analysisResult.confidence, processingTime: analysisResult.elapsed + 'ms' }
    });
  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error('Report error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 4. Get Reports (pending)
app.get('/api/waste-reports', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 5. Get single report
app.get('/api/waste-reports/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ message: 'Report not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Fetch error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 6. Clean report (municipal only)
app.put('/api/clean-report/:id', authenticateToken, upload.single('cleanedImage'), async (req, res) => {
  if (req.user.role !== 'municipal') {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    return res.status(403).json({ message: 'Municipal users only' });
  }
  if (!req.file) return res.status(400).json({ message: 'Cleaned image required' });

  try {
    const reportQ = await pool.query('SELECT * FROM waste_reports WHERE id = $1', [req.params.id]);
    if (reportQ.rows.length === 0) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      return res.status(404).json({ message: 'Report not found' });
    }
    const original = reportQ.rows[0];
    const beforeImagePath = localImagePathFromUrl(original.image_url);
    const afterImagePath = req.file.path;

    const verification = await verifyCleanup(beforeImagePath, afterImagePath);
    const cleanedImageUrl = '/uploads/' + req.file.filename;

    const updateQ = `
      UPDATE waste_reports
      SET is_cleaned = TRUE,
          cleaned_by_user_id = $1,
          cleaned_image_url = $2,
          cleaned_at = CURRENT_TIMESTAMP,
          cleanup_verified = $3,
          verification_confidence = $4,
          ai_comparison_result = $5
      WHERE id = $6
      RETURNING *
    `;
    const updateValues = [req.user.id, cleanedImageUrl, verification.verified, verification.confidence, verification.aiResponse, req.params.id];
    const updateResult = await pool.query(updateQ, updateValues);

    res.json({
      message: verification.verified ? 'Cleanup verified successfully!' : 'Cleanup submitted - manual review may be required',
      report: updateResult.rows[0],
      verification: {
        verified: verification.verified,
        confidence: verification.confidence,
        similarImages: verification.similarImages,
        aiResponse: verification.aiResponse,
        processingTime: verification.elapsed + 'ms'
      }
    });
  } catch (err) {
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error('Cleanup error:', err);
    res.status(500).json({ message: 'Server error: ' + (err && err.message ? err.message : err) });
  }
});

// 7. Leaderboard
app.get('/api/leaderboard', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT reported_by, SUM(points) AS total_points, COUNT(*) AS total_reports
       FROM waste_reports
       WHERE reported_by IS NOT NULL AND reported_by != '' AND reported_by != 'Anonymous'
       GROUP BY reported_by
       ORDER BY total_points DESC
       LIMIT 10`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 8. Statistics
app.get('/api/statistics', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         COUNT(*) as total_reports,
         COUNT(CASE WHEN is_cleaned = TRUE THEN 1 END) as cleaned_reports,
         COUNT(CASE WHEN is_cleaned = FALSE THEN 1 END) as pending_reports,
         SUM(points) as total_points,
         COUNT(DISTINCT reported_by) as unique_reporters
       FROM waste_reports`
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 9. Health check
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      database: 'connected',
      gemini: process.env.GEMINI_API_KEY ? 'configured' : 'missing',
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ status: 'unhealthy', error: err.message });
  }
});

// 10. Municipal endpoints
app.get('/api/municipal/pending', authenticateToken, async (req, res) => {
  if (req.user.role !== 'municipal') return res.status(403).json({ message: 'Access denied' });
  try {
    const result = await pool.query('SELECT * FROM waste_reports WHERE is_cleaned = FALSE ORDER BY reported_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Municipal pending error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/municipal/stats', authenticateToken, async (req, res) => {
  if (req.user.role !== 'municipal') return res.status(403).json({ message: 'Access denied' });
  try {
    const stats = await pool.query(`
      SELECT
        COUNT(*) as total_cleaned,
        COUNT(CASE WHEN cleanup_verified = TRUE THEN 1 END) as verified_cleanups,
        COUNT(CASE WHEN cleanup_verified = FALSE THEN 1 END) as unverified_cleanups,
        COUNT(CASE WHEN verification_confidence = 'high' THEN 1 END) as high_confidence,
        COUNT(CASE WHEN verification_confidence = 'medium' THEN 1 END) as medium_confidence,
        COUNT(CASE WHEN verification_confidence = 'low' THEN 1 END) as low_confidence
      FROM waste_reports WHERE is_cleaned = TRUE
    `);
    res.json(stats.rows[0]);
  } catch (err) {
    console.error('Municipal stats error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/municipal/history', authenticateToken, async (req, res) => {
  if (req.user.role !== 'municipal') return res.status(403).json({ message: 'Access denied' });
  try {
    const result = await pool.query('SELECT * FROM waste_reports WHERE cleaned_by_user_id = $1 ORDER BY cleaned_at DESC LIMIT 50', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error('Municipal history error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ========== Error handling middleware (JSON responses) ==========
app.use((err, req, res, next) => {
  console.error('Global error:', err && err.stack ? err.stack : err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ message: 'File too large (10MB max)' });
    return res.status(400).json({ message: err.message });
  }
  // If client expects JSON, return JSON error
  if (req.path && req.path.startsWith('/api/')) {
    return res.status(500).json({ message: err.message || 'Server error' });
  }
  // Otherwise fall back to plain text
  res.status(500).send(err.message || 'Server error');
});

// ========== SPA support: serve index.html for non-API routes ==========
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  return res.status(404).send('Not found');
});

// ========== Start server ==========
app.listen(PORT, () => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🚀 ENVIROTRACK SERVER STARTED');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🌐 Server running on port ' + PORT);
  console.log('📊 API: Ready');
  console.log('✅ GPS Validation: Active');
  console.log('🤖 AI Model: gemini-2.0-flash-exp');
  console.log('🔑 Gemini API: ' + (process.env.GEMINI_API_KEY ? 'Configured ✅' : 'Missing ❌'));
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
