<?php
/*
Sample vulnerable admin panel with SQL injection vulnerabilities
This file is for TESTING PURPOSES ONLY - demonstrates insecure PHP coding practices
*/

class AdminPanel {
    private $connection;
    
    public function __construct() {
        $this->connection = new mysqli("localhost", "admin", "password", "admin_db");
    }
    
    /**
     * VULNERABLE: Direct concatenation in SQL query
     * Allows SQL injection in admin authentication
     */
    public function adminLogin($username, $password) {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "SELECT * FROM admins WHERE username = '" . $username . "' AND password = '" . $password . "'";
        $result = $this->connection->query($query);
        
        return $result->fetch_assoc();
    }
    
    /**
     * VULNERABLE: Direct interpolation in SQL query
     * SQL injection in user management
     */
    public function getUserById($userId) {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "SELECT * FROM users WHERE id = $userId";
        $result = $this->connection->query($query);
        
        return $result->fetch_all(MYSQLI_ASSOC);
    }
    
    /**
     * VULNERABLE: String concatenation in WHERE clause
     * SQL injection in search functionality
     */
    public function searchUsers($searchTerm) {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "SELECT username, email, status FROM users WHERE username LIKE '%" . $searchTerm . "%' OR email LIKE '%" . $searchTerm . "%'";
        $result = $this->connection->query($query);
        
        return $result->fetch_all(MYSQLI_ASSOC);
    }
    
    /**
     * VULNERABLE: Direct concatenation in UPDATE query
     * SQL injection in user status update
     */
    public function updateUserStatus($userId, $status) {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "UPDATE users SET status = '" . $status . "' WHERE id = " . $userId;
        $result = $this->connection->query($query);
        
        return $result;
    }
    
    /**
     * VULNERABLE: Direct concatenation in INSERT query
     * SQL injection in log insertion
     */
    public function logAdminAction($adminId, $action, $details) {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "INSERT INTO admin_logs (admin_id, action, details, timestamp) VALUES (" . $adminId . ", '" . $action . "', '" . $details . "', NOW())";
        $result = $this->connection->query($query);
        
        return $result;
    }
    
    /**
     * VULNERABLE: Direct concatenation in ORDER BY clause
     * SQL injection in sorting functionality
     */
    public function getUsersOrderedBy($orderBy, $direction = 'ASC') {
        // VULNERABLE CODE - DO NOT USE IN PRODUCTION
        $query = "SELECT * FROM users ORDER BY " . $orderBy . " " . $direction;
        $result = $this->connection->query($query);
        
        return $result->fetch_all(MYSQLI_ASSOC);
    }
}

// Usage examples with vulnerable endpoints
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $admin = new AdminPanel();
    
    if (isset($_POST['login'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $result = $admin->adminLogin($username, $password);
        
        if ($result) {
            $_SESSION['admin_id'] = $result['id'];
            echo json_encode(["status" => "success", "message" => "Login successful"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Invalid credentials"]);
        }
    }
    
    if (isset($_POST['search'])) {
        $searchTerm = $_POST['search_term'];
        $results = $admin->searchUsers($searchTerm);
        echo json_encode($results);
    }
    
    if (isset($_POST['update_status'])) {
        $userId = $_POST['user_id'];
        $status = $_POST['status'];
        $admin->updateUserStatus($userId, $status);
        echo json_encode(["status" => "success"]);
    }
}

// GET request handlers
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $admin = new AdminPanel();
    
    if (isset($_GET['user_id'])) {
        $userId = $_GET['user_id'];
        $user = $admin->getUserById($userId);
        echo json_encode($user);
    }
    
    if (isset($_GET['sort'])) {
        $orderBy = $_GET['sort'];
        $direction = $_GET['direction'] ?? 'ASC';
        $users = $admin->getUsersOrderedBy($orderBy, $direction);
        echo json_encode($users);
    }
}
?> 