const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const PORT = process.env.PORT || 3000;
const ADMIN_PIN = process.env.ADMIN_PIN || "2026";
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');

// مسار التخزين الدائم على Railway
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
const DB_PATH = path.join(DATA_DIR, 'production.sqlite');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// محدد معدل الطلبات لحماية السيرفر من الإغراق
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 150,
    message: { success: false, message: 'طلبات مكثفة، يرجى المحاولة بعد لحظات.' }
});
app.use('/api/', apiLimiter);

// -------------------------------------------------------------
// قاعدة البيانات بنمط WAL
// -------------------------------------------------------------
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('Database connection error:', err.message);
    else console.log(`Database connected successfully at: ${DB_PATH}`);
});

db.serialize(() => {
    db.run("PRAGMA journal_mode = WAL;");
    db.run("PRAGMA synchronous = NORMAL;");

    db.run(`
        CREATE TABLE IF NOT EXISTS professors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            department TEXT NOT NULL,
            phone TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            professor_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (professor_id) REFERENCES professors (id) ON DELETE SET NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            course_name TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            radius_meters REAL NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            student_id TEXT NOT NULL,
            student_name TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            distance_meters REAL,
            ip_address TEXT,
            scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES sessions (id),
            UNIQUE(session_id, student_id),
            UNIQUE(session_id, device_fingerprint)
        )
    `);
});

// -------------------------------------------------------------
// الدوال المساعدة والتشفير والتوثيق
// -------------------------------------------------------------
function generateDynamicToken(secretKey, sessionId, stepOffset = 0) {
    const timeStep = 10;
    const currentStep = Math.floor(Date.now() / 1000 / timeStep) + stepOffset;
    return crypto
        .createHmac('sha256', secretKey)
        .update(`${sessionId}:${currentStep}`)
        .digest('hex')
        .substring(0, 16);
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371000;
    const toRad = (v) => (v * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    return R * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

function generateAdminToken() {
    const expiry = Date.now() + (8 * 60 * 60 * 1000);
    const payload = `admin:${expiry}`;
    const signature = crypto.createHmac('sha256', ADMIN_SECRET).update(payload).digest('hex');
    return Buffer.from(`${payload}:${signature}`).toString('base64');
}

function verifyAdminToken(token) {
    try {
        const decoded = Buffer.from(token, 'base64').toString('utf8');
        const [role, expiryStr, signature] = decoded.split(':');
        if (role !== 'admin' || Date.now() > parseInt(expiryStr)) return false;
        const expectedSignature = crypto.createHmac('sha256', ADMIN_SECRET).update(`${role}:${expiryStr}`).digest('hex');
        return signature === expectedSignature;
    } catch {
        return false;
    }
}

function requireAdminAuth(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, message: 'غير مصرح: يرجى تسجيل الدخول كمسؤول' });
    }
    const token = authHeader.split(' ')[1];
    if (!verifyAdminToken(token)) {
        return res.status(401).json({ success: false, message: 'انتهت صلاحية الجلسة، أعد إدخال الرمز' });
    }
    next();
}

// -------------------------------------------------------------
// Real-time (Socket.io)
// -------------------------------------------------------------
io.on('connection', (socket) => {
    socket.on('join_lecture', (sessionId) => {
        socket.join(`lecture_${sessionId}`);
    });
});

// -------------------------------------------------------------
// مسارات توثيق الإدارة (Admin Auth & Endpoints)
// -------------------------------------------------------------
app.post('/api/admin/login', (req, res) => {
    const { pin } = req.body;
    if (!pin || pin.toString() !== ADMIN_PIN.toString()) {
        return res.status(403).json({ success: false, message: 'رمز الدخول السري غير صحيح!' });
    }
    res.json({ success: true, token: generateAdminToken() });
});

app.get('/api/admin/stats', requireAdminAuth, (req, res) => {
    const stats = {};
    db.get('SELECT COUNT(*) as totalProfessors FROM professors', (e1, r1) => {
        stats.totalProfessors = r1 ? r1.totalProfessors : 0;
        db.get('SELECT COUNT(*) as totalCourses FROM courses', (e2, r2) => {
            stats.totalCourses = r2 ? r2.totalCourses : 0;
            db.get('SELECT COUNT(*) as totalAttendance FROM attendance', (e3, r3) => {
                stats.totalAttendance = r3 ? r3.totalAttendance : 0;
                db.get('SELECT COUNT(*) as activeSessions FROM sessions WHERE is_active = 1', (e4, r4) => {
                    stats.activeSessions = r4 ? r4.activeSessions : 0;
                    res.json({ success: true, stats });
                });
            });
        });
    });
});

app.get('/api/admin/professors', requireAdminAuth, (req, res) => {
    db.all('SELECT * FROM professors ORDER BY id DESC', (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, professors: rows });
    });
});

app.post('/api/admin/professors', requireAdminAuth, (req, res) => {
    const { name, email, department, phone } = req.body;
    if (!name || !email || !department) {
        return res.status(400).json({ success: false, message: 'الاسم، البريد والقسم حقول إجبارية' });
    }
    db.run(
        'INSERT INTO professors (name, email, department, phone) VALUES (?, ?, ?, ?)',
        [name.trim(), email.trim(), department.trim(), phone || ''],
        function(err) {
            if (err) return res.status(409).json({ success: false, message: 'البريد الإلكتروني مسجل مسبقاً' });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.delete('/api/admin/professors/:id', requireAdminAuth, (req, res) => {
    db.run('DELETE FROM professors WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// متاح عام لشاشة المحاضر ومحمي في العرض الإداري
app.get('/api/courses/public', (req, res) => {
    db.all(`
        SELECT c.*, p.name as professor_name 
        FROM courses c 
        LEFT JOIN professors p ON c.professor_id = p.id 
        ORDER BY c.id DESC
    `, (err, rows) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, courses: rows });
    });
});

app.get('/api/admin/courses', requireAdminAuth, (req, res) => {
    db.all(`
        SELECT c.*, p.name as professor_name 
        FROM courses c 
        LEFT JOIN professors p ON c.professor_id = p.id 
        ORDER BY c.id DESC
    `, (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, courses: rows });
    });
});

app.post('/api/admin/courses', requireAdminAuth, (req, res) => {
    const { code, name, department, professorId } = req.body;
    if (!code || !name || !department) {
        return res.status(400).json({ success: false, message: 'كود المقرر واسمه وقسمه مطلوبة' });
    }
    db.run(
        'INSERT INTO courses (code, name, department, professor_id) VALUES (?, ?, ?, ?)',
        [code.trim().toUpperCase(), name.trim(), department.trim(), professorId || null],
        function(err) {
            if (err) return res.status(409).json({ success: false, message: 'رمز المقرر مسجل بالفعل' });
            res.json({ success: true, id: this.lastID });
        }
    );
});

app.delete('/api/admin/courses/:id', requireAdminAuth, (req, res) => {
    db.run('DELETE FROM courses WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

app.get('/api/admin/sessions', requireAdminAuth, (req, res) => {
    db.all(`
        SELECT s.*, COUNT(a.id) as attendees_count 
        FROM sessions s 
        LEFT JOIN attendance a ON s.id = a.session_id 
        GROUP BY s.id 
        ORDER BY s.created_at DESC
    `, (err, rows) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, sessions: rows });
    });
});

app.post('/api/admin/sessions/:id/force-close', requireAdminAuth, (req, res) => {
    db.run('UPDATE sessions SET is_active = 0 WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false });
        io.to(`lecture_${req.params.id}`).emit('session_closed');
        res.json({ success: true });
    });
});

// -------------------------------------------------------------
// مسارات المحاضرة والطالب (Sessions & Attendance)
// -------------------------------------------------------------
app.post('/api/sessions/create', (req, res) => {
    const { courseName, latitude, longitude, radiusMeters } = req.body;
    if (!courseName) return res.status(400).json({ success: false, message: 'اسم المقرر مطلوب' });

    const sessionId = 'LEC-' + crypto.randomBytes(3).toString('hex').toUpperCase();
    const secretKey = crypto.randomBytes(32).toString('hex');
    const radius = Number(radiusMeters) || 35;

    db.run(
        `INSERT INTO sessions (id, course_name, secret_key, latitude, longitude, radius_meters) VALUES (?, ?, ?, ?, ?, ?)`,
        [sessionId, courseName, secretKey, latitude || 0, longitude || 0, radius],
        function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, sessionId, courseName, radiusMeters: radius });
        }
    );
});

app.get('/api/sessions/:id/token', (req, res) => {
    const sessionId = req.params.id;
    db.get('SELECT * FROM sessions WHERE id = ? AND is_active = 1', [sessionId], (err, session) => {
        if (err || !session) return res.status(404).json({ success: false, message: 'المحاضرة غير متاحة' });

        const token = generateDynamicToken(session.secret_key, session.id, 0);
        const remaining = 10 - (Math.floor(Date.now() / 1000) % 10);
        res.json({ success: true, sessionId: session.id, token, remaining });
    });
});

app.post('/api/attendance/verify', (req, res) => {
    const { sessionId, token, studentId, studentName, fingerprint, latitude, longitude } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    if (!sessionId || !token || !studentId || !studentName || !fingerprint) {
        return res.status(400).json({ success: false, message: 'البيانات المرسلة غير مكتملة' });
    }

    db.get('SELECT * FROM sessions WHERE id = ? AND is_active = 1', [sessionId], (err, session) => {
        if (err || !session) return res.status(404).json({ success: false, message: 'جلسة المحاضرة مغلقة أو غير موجودة' });

        const currentToken = generateDynamicToken(session.secret_key, session.id, 0);
        const previousToken = generateDynamicToken(session.secret_key, session.id, -1);

        if (token !== currentToken && token !== previousToken) {
            return res.status(403).json({ success: false, message: 'رمز QR منتهي الصلاحية! يرجى مسح الرمز الجديد المتزامن على الشاشة.' });
        }

        let distance = 0;
        if (session.latitude !== 0 && session.longitude !== 0) {
            if (!latitude || !longitude) {
                return res.status(400).json({ success: false, message: 'يجب السماح بخدمة الـ GPS للتحقق من تواجدك' });
            }
            distance = calculateDistance(session.latitude, session.longitude, latitude, longitude);
            if (distance > session.radius_meters) {
                return res.status(403).json({
                    success: false,
                    message: `فشل التحقق المكاني: أنت تبعد ${Math.round(distance)}م (المسموح: ${session.radius_meters}م)`
                });
            }
        }

        const query = `
            INSERT INTO attendance (session_id, student_id, student_name, device_fingerprint, latitude, longitude, distance_meters, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.run(query, [sessionId, studentId.trim(), studentName.trim(), fingerprint, latitude, longitude, distance, ip], function(insertErr) {
            if (insertErr) {
                if (insertErr.message.includes('attendance.session_id, attendance.student_id')) {
                    return res.status(409).json({ success: false, message: 'لقد تم تسجيل حضورك مسبقاً في هذه المحاضرة' });
                }
                if (insertErr.message.includes('attendance.session_id, attendance.device_fingerprint')) {
                    return res.status(409).json({ success: false, message: 'مخالفة أمنية: هذا الجهاز مسجل لطالب آخر في نفس المحاضرة!' });
                }
                return res.status(500).json({ success: false, message: insertErr.message });
            }

            const record = {
                student_id: studentId,
                student_name: studentName,
                scan_time: new Date().toLocaleTimeString('ar-IQ'),
                distance: Math.round(distance)
            };

            io.to(`lecture_${sessionId}`).emit('new_attendee', record);
            res.json({ success: true, message: 'تم اعتماد حضورك وتوثيقه بنجاح', data: record });
        });
    });
});

app.post('/api/sessions/:id/close', (req, res) => {
    db.run('UPDATE sessions SET is_active = 0 WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        io.to(`lecture_${req.params.id}`).emit('session_closed');
        res.json({ success: true, message: 'تم إغلاق المحاضرة' });
    });
});

app.get('/api/sessions/:id/export', (req, res) => {
    const sessionId = req.params.id;
    db.all('SELECT student_id, student_name, scan_time, distance_meters, ip_address FROM attendance WHERE session_id = ? ORDER BY scan_time ASC', [sessionId], (err, rows) => {
        if (err) return res.status(500).send('Database Error');
        let csv = '\uFEFFالرقم الجامعي,اسم الطالب,وقت التسجيل,المسافة المحسوبة (متر),عنوان IP\n';
        rows.forEach(r => {
            csv += `"${r.student_id}","${r.student_name}","${r.scan_time}","${Math.round(r.distance_meters || 0)}","${r.ip_address}"\n`;
        });
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="Attendance-${sessionId}.csv"`);
        res.send(csv);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port: ${PORT}`);
});
