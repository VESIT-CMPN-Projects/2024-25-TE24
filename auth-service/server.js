require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Connect to MySQL Database
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'mydatabase'
});

// Check Database Connection
db.connect(err => {
    if (err) {
        console.error('❌ MySQL Connection Failed:', err.message);
        process.exit(1); // Exit if the database is not connected
    } else {
        console.log('✅ Connected to MySQL Database');
        
        // Create users table if it doesn't exist
        const createUsersTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`;
        
        db.query(createUsersTableQuery, (err, result) => {
            if (err) {
                console.error('❌ Failed to create users table:', err.message);
            } else {
                console.log('✅ users table ready');
            }
        });
        
        // Create contact_messages table if it doesn't exist
        const createContactTableQuery = `
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL,
            subject VARCHAR(200) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`;
        
        db.query(createContactTableQuery, (err, result) => {
            if (err) {
                console.error('❌ Failed to create contact_messages table:', err.message);
            } else {
                console.log('✅ contact_messages table ready');
            }
        });
    }
});

// Enable CORS for all routes
app.use(cors());
// Increase payload size limit
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// User Registration Endpoint - Keep original path and add API version
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (results.length > 0) {
                return res.status(400).json({ message: 'User already exists' });
            }
            // Hash password before saving
            const hashedPassword = await bcrypt.hash(password, 10);
            // Insert new user into MySQL
            db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
                [name, email, hashedPassword], 
                (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    res.status(201).json({ message: 'User registered successfully' });
                }
            );
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add API version of registration endpoint for consistency
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (results.length > 0) {
                return res.status(400).json({ message: 'User already exists' });
            }
            // Hash password before saving
            const hashedPassword = await bcrypt.hash(password, 10);
            // Insert new user into MySQL
            db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', 
                [name, email, hashedPassword], 
                (err, result) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    res.status(201).json({ message: 'User registered successfully' });
                }
            );
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User Login Endpoint - Keep original path
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("Login attempt for:", email);
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error("Database error during login:", err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (results.length === 0) {
                console.log("No user found with email:", email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            
            const user = results[0];
            
            // Compare password with stored hash
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.log("Password doesn't match for user:", email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            
            // Generate JWT token
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            console.log("Login successful for:", email);
            res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
        });
    } catch (error) {
        console.error("Server error during login:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add API version of login endpoint to match frontend expectation
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log("API Login attempt for:", email);
        
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }
        
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) {
                console.error("Database error during API login:", err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (results.length === 0) {
                console.log("API login: No user found with email:", email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            
            const user = results[0];
            
            // Compare password with stored hash
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                console.log("API login: Password doesn't match for user:", email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }
            
            // Generate JWT token
            const token = jwt.sign(
                { id: user.id, email: user.email, name: user.name },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            console.log("API login successful for:", email);
            res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
        });
    } catch (error) {
        console.error("Server error during API login:", error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add forgot password endpoint
app.post('/api/forgot-password', (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }
        
        // Check if user exists
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            // For security reasons, always return success even if email doesn't exist
            res.json({ message: 'If your email exists, password reset instructions will be sent' });
            
            // In a real application, send an email with reset instructions here
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Contact Form Submission Endpoint - FIXED VERSION
app.post('/api/contact', (req, res) => {
    try {
        console.log("Contact form submission received:", req.body);
        const { name, email, subject, message } = req.body;
        
        // Validate required fields
        if (!name || !email || !subject || !message) {
            console.log("Missing required fields:", { name, email, subject, message });
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }
        
        console.log("Inserting contact message into database...");
        // Insert data into database
        db.query(
            'INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
            [name, email, subject, message],
            (err, result) => {
                if (err) {
                    console.error('Error saving contact message:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Database error. Please try again later.'
                    });
                }
                
                console.log("Database insert result:", result);
                if (result.affectedRows === 1) {
                    console.log("Contact message saved successfully");
                    return res.status(201).json({
                        success: true,
                        message: 'Message sent successfully'
                    });
                } else {
                    console.log("Failed to save contact message");
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to save message'
                    });
                }
            }
        );
    } catch (error) {
        console.error('Error saving contact message:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Also add the contact endpoint without the /api prefix for consistency
app.post('/contact', (req, res) => {
    try {
        console.log("Contact form submission received at /contact:", req.body);
        const { name, email, subject, message } = req.body;
        
        // Validate required fields
        if (!name || !email || !subject || !message) {
            console.log("Missing required fields:", { name, email, subject, message });
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }
        
        console.log("Inserting contact message into database...");
        // Insert data into database
        db.query(
            'INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
            [name, email, subject, message],
            (err, result) => {
                if (err) {
                    console.error('Error saving contact message:', err);
                    return res.status(500).json({
                        success: false,
                        message: 'Database error. Please try again later.'
                    });
                }
                
                console.log("Database insert result:", result);
                if (result.affectedRows === 1) {
                    console.log("Contact message saved successfully");
                    return res.status(201).json({
                        success: true,
                        message: 'Message sent successfully'
                    });
                } else {
                    console.log("Failed to save contact message");
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to save message'
                    });
                }
            }
        );
    } catch (error) {
        console.error('Error saving contact message:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error. Please try again later.'
        });
    }
});

// Endpoint to retrieve contact form submissions (protected by JWT)
app.get('/api/contact', authenticateToken, (req, res) => {
    db.query('SELECT * FROM contact_messages ORDER BY created_at DESC', (err, results) => {
        if (err) {
            console.error('Error fetching contact messages:', err);
            return res.status(500).json({
                success: false,
                message: 'Database error'
            });
        }
        
        return res.status(200).json({
            success: true,
            data: results
        });
    });
});

// Health check endpoint to verify server/DB connection
app.get('/api/health', (req, res) => {
    db.ping((err) => {
        if (err) {
            return res.status(500).json({
                status: 'error',
                message: 'Database connection failed',
                error: err.message
            });
        }
        res.status(200).json({
            status: 'ok',
            message: 'Server is running and database is connected'
        });
    });
});

// Add endpoint to check database tables
app.get('/api/debug/tables', (req, res) => {
    db.query('SHOW TABLES', (err, results) => {
        if (err) {
            return res.status(500).json({
                status: 'error',
                message: 'Could not query tables',
                error: err.message
            });
        }
        
        const tables = results.map(row => Object.values(row)[0]);
        
        // Get each table's structure
        const tablePromises = tables.map(table => {
            return new Promise((resolve, reject) => {
                db.query(`DESCRIBE ${table}`, (err, columns) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ table, columns });
                    }
                });
            });
        });
        
        Promise.all(tablePromises)
            .then(tableDetails => {
                res.status(200).json({
                    status: 'ok',
                    tables: tableDetails
                });
            })
            .catch(error => {
                res.status(500).json({
                    status: 'error',
                    message: 'Error fetching table details',
                    error: error.message
                });
            });
    });
});

// Add endpoint to check contact_messages content
app.get('/api/debug/contact_messages', (req, res) => {
    db.query('SELECT * FROM contact_messages', (err, results) => {
        if (err) {
            return res.status(500).json({
                status: 'error',
                message: 'Could not query contact_messages',
                error: err.message
            });
        }
        
        res.status(200).json({
            status: 'ok',
            count: results.length,
            messages: results
        });
    });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Start Server
app.listen(port, () => {
    console.log(`🚀 Server running on http://localhost:${port}`);
});