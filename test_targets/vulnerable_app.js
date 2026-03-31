/**
 * 보안 취약점 테스트용 JavaScript/Node.js 샘플
 *
 * 포함된 취약점:
 * - SQL Injection (CWE-89)
 * - Command Injection (CWE-78)
 * - XSS (CWE-79)
 * - Hardcoded Secrets (CWE-798)
 * - Insecure Cookie (CWE-614)
 * - Prototype Pollution (CWE-1321)
 * - Path Traversal (CWE-22)
 */

const express = require('express');
const mysql = require('mysql');
const { exec, execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// [취약] 하드코딩된 비밀 키 (CWE-798)
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const API_KEY = "sk-proj-abcdef123456789";
const DB_PASSWORD = "root_password_123";

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,  // [취약] 하드코딩된 비밀번호
    database: 'myapp'
});


// =========================================
// 1. SQL Injection (CWE-89)
// =========================================

// [취약] 문자열 결합으로 SQL 쿼리 생성
app.get('/api/user', (req, res) => {
    const userId = req.query.id;
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// [취약] 템플릿 리터럴로 SQL 쿼리 생성
app.get('/api/search', (req, res) => {
    const keyword = req.query.q;
    const query = `SELECT * FROM products WHERE name LIKE '%${keyword}%'`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});


// =========================================
// 2. Command Injection (CWE-78)
// =========================================

// [취약] exec에 사용자 입력 직접 전달
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 3 ' + host, (err, stdout, stderr) => {
        res.send(stdout || stderr);
    });
});

// [취약] execSync에 사용자 입력 전달
app.get('/api/lookup', (req, res) => {
    const domain = req.query.domain;
    try {
        const result = execSync(`nslookup ${domain}`).toString();
        res.send(result);
    } catch (e) {
        res.status(500).send(e.message);
    }
});


// =========================================
// 3. XSS - Cross Site Scripting (CWE-79)
// =========================================

// [취약] 사용자 입력을 HTML에 직접 삽입 (Reflected XSS)
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`
        <html>
        <body>
            <h1>Search Results</h1>
            <p>Results for: ${query}</p>
        </body>
        </html>
    `);
});

// [취약] innerHTML 설정 (DOM XSS)
app.get('/profile', (req, res) => {
    const username = req.query.name;
    res.send(`
        <html>
        <body>
            <div id="greeting"></div>
            <script>
                document.getElementById('greeting').innerHTML = 'Hello, ${username}!';
            </script>
        </body>
        </html>
    `);
});


// =========================================
// 4. Path Traversal (CWE-22)
// =========================================

// [취약] 사용자 입력을 파일 경로에 직접 사용
app.get('/api/file', (req, res) => {
    const filename = req.query.name;
    const filePath = path.join('/uploads', filename);
    // ../../../etc/passwd 같은 입력으로 시스템 파일 접근 가능
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('File not found');
        res.send(data);
    });
});


// =========================================
// 5. Insecure Cookie (CWE-614)
// =========================================

// [취약] HttpOnly, Secure 플래그 없는 쿠키
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // 인증 로직 생략...
    const token = crypto.createHash('md5').update(username + password).digest('hex');

    // [취약] secure, httpOnly 미설정
    res.cookie('session', token, {
        maxAge: 86400000,
        // secure: true,    // 누락
        // httpOnly: true,  // 누락
    });
    res.json({ message: 'Login successful' });
});


// =========================================
// 6. Weak Cryptography (CWE-327)
// =========================================

// [취약] MD5 해시 사용
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// [취약] eval 사용 (CWE-95)
app.post('/api/calculate', (req, res) => {
    const expression = req.body.expression;
    try {
        const result = eval(expression);  // [취약] 임의 코드 실행 가능
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});


// =========================================
// 서버 시작
// =========================================

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
