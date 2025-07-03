/**
 * Sample vulnerable database service with SQL injection vulnerabilities
 * This file is for TESTING PURPOSES ONLY - demonstrates insecure Node.js coding practices
 */

const mysql = require('mysql2');
const express = require('express');
const app = express();

// Database connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'myapp'
});

/**
 * VULNERABLE: Template literal with direct interpolation
 * SQL injection in user authentication
 */
async function authenticateUser(email, password) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            resolve(results[0]);
        });
    });
}

/**
 * VULNERABLE: String concatenation in SQL query
 * SQL injection in product search
 */
function searchProducts(searchTerm, category) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%' AND category = '" + category + "'";
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            resolve(results);
        });
    });
}

/**
 * VULNERABLE: Direct interpolation in UPDATE query
 * SQL injection in user profile update
 */
function updateUserProfile(userId, name, email, phone) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const query = `UPDATE users SET name = '${name}', email = '${email}', phone = '${phone}' WHERE id = ${userId}`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            resolve(results);
        });
    });
}

/**
 * VULNERABLE: String concatenation in ORDER BY clause
 * SQL injection in sorting functionality
 */
function getOrdersSortedBy(sortColumn, sortDirection) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const query = "SELECT * FROM orders ORDER BY " + sortColumn + " " + sortDirection;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            resolve(results);
        });
    });
}

/**
 * VULNERABLE: Direct concatenation in LIMIT clause
 * SQL injection in pagination
 */
function getUsersPaginated(page, limit) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const offset = page * limit;
    const query = "SELECT * FROM users LIMIT " + limit + " OFFSET " + offset;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            resolve(results);
        });
    });
}

/**
 * VULNERABLE: Template literal in DELETE query
 * SQL injection in data deletion
 */
function deleteUserAccount(userId, reason) {
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    const query = `DELETE FROM users WHERE id = ${userId} AND status = 'inactive'`;
    const logQuery = `INSERT INTO deletion_log (user_id, reason, timestamp) VALUES (${userId}, '${reason}', NOW())`;
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            if (error) reject(error);
            
            // Log the deletion
            connection.query(logQuery, (logError) => {
                if (logError) console.error('Logging failed:', logError);
                resolve(results);
            });
        });
    });
}

// Express.js routes with vulnerable endpoints
app.use(express.json());

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await authenticateUser(email, password);
        
        if (user) {
            res.json({ success: true, user: user });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/products/search', async (req, res) => {
    try {
        const { q, category } = req.query;
        const products = await searchProducts(q, category);
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/profile/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, phone } = req.body;
        await updateUserProfile(userId, name, email, phone);
        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/orders', async (req, res) => {
    try {
        const { sort, direction } = req.query;
        const orders = await getOrdersSortedBy(sort || 'id', direction || 'ASC');
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/users', async (req, res) => {
    try {
        const { page, limit } = req.query;
        const users = await getUsersPaginated(parseInt(page) || 0, parseInt(limit) || 10);
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { reason } = req.body;
        await deleteUserAccount(userId, reason);
        res.json({ success: true, message: 'User account deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 