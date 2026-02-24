# PHP Security Test Examples

Copy and paste each example into the PHP Vulnerability Analyzer GUI to test detection.

---

## Example 1: SQL Injection

```php
<?php
// User search feature - vulnerable to SQL injection
$conn = mysqli_connect("localhost", "root", "", "webapp_db");

$username = $_GET['username'];
$password = $_POST['password'];

// Direct concatenation into SQL query
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    $row = mysqli_fetch_assoc($result);
    echo "Welcome, " . $row['username'];
} else {
    echo "Invalid credentials";
}

// Another vulnerable query using sprintf
$search = $_GET['search'];
$sql = sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", $search);
$products = mysqli_query($conn, $sql);

// Vulnerable ORDER BY
$sort = $_REQUEST['sort'];
$query2 = "SELECT * FROM items ORDER BY " . $sort;
mysqli_query($conn, $query2);

mysqli_close($conn);
?>
```

---

## Example 2: SSRF (Server-Side Request Forgery)

```php
<?php
// Image proxy service - vulnerable to SSRF
$image_url = $_GET['url'];

// Directly fetching user-provided URL
$image_data = file_get_contents($image_url);
header('Content-Type: image/jpeg');
echo $image_data;

// API proxy endpoint - also vulnerable
$api_endpoint = $_POST['endpoint'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $api_endpoint);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$response = curl_exec($ch);
curl_close($ch);

echo $response;

// DNS lookup with user input
$hostname = $_GET['host'];
$ip = gethostbyname($hostname);
$records = dns_get_record($hostname, DNS_A);

// Webhook callback
$webhook = $_POST['callback_url'];
$payload = json_encode(['status' => 'done']);
$context = stream_context_create(['http' => [
    'method' => 'POST',
    'content' => $payload
]]);
file_get_contents($webhook, false, $context);
?>
```

---

## Example 3: Authentication Bypass

```php
<?php
session_start();

// Login handler - vulnerable to auth bypass
$username = $_POST['username'];
$password = $_POST['password'];

// Weak comparison operator (type juggling vulnerable)
$stored_password = get_password($username);
if ($password == $stored_password) {
    $_SESSION['logged_in'] = true;
    $_SESSION['user'] = $username;
}

// strcmp bypass - returns NULL for array input
$admin_key = "supersecretkey123";
if (strcmp($_POST['admin_key'], $admin_key) == 0) {
    $_SESSION['admin'] = true;
}

// MD5 magic hash comparison
$otp = $_GET['otp'];
if (md5($otp) == "0e462097431906509019562988736854") {
    grant_access();
}

// Cookie-based auth with no server validation
if (isset($_COOKIE['admin']) && $_COOKIE['admin'] == 'true') {
    include 'admin_panel.php';
}

// extract() overwrites local variables
extract($_POST);
if ($is_admin) {
    show_admin_dashboard();
}

// Unsafe deserialization
$user_data = unserialize($_COOKIE['user_session']);
if ($user_data['role'] === 'admin') {
    admin_functions();
}

// Session fixation
$sid = $_GET['session_id'];
session_id($sid);
session_start();
$_SESSION['auth'] = $_POST['username'];
?>
```

---

## Example 4: Input Validation Issues

```php
<?php
// User profile page - multiple input validation failures

// Direct output without sanitization (XSS)
$name = $_GET['name'];
echo "Hello, " . $name;

$comment = $_POST['comment'];
print "<div class='comment'>$comment</div>";

// File inclusion with user input (LFI/RFI)
$page = $_GET['page'];
include($page . '.php');

$template = $_REQUEST['template'];
require("templates/" . $template);

// Command injection
$ip_address = $_POST['ip'];
system("ping -c 4 " . $ip_address);

$filename = $_GET['file'];
$output = shell_exec("cat " . $filename);
echo "<pre>$output</pre>";

// eval() with user input
$expression = $_GET['calc'];
eval('$result = ' . $expression . ';');

// Unsafe file upload
$upload_name = $_FILES['avatar']['name'];
$tmp_path = $_FILES['avatar']['tmp_name'];
move_uploaded_file($tmp_path, "uploads/" . $upload_name);

// Header injection
$redirect = $_GET['redirect'];
header("Location: " . $redirect);

// Mail injection
$from = $_POST['email'];
$headers = "From: $from\r\n";
mail("admin@example.com", "Contact Form", $_POST['message'], $headers);
?>
```

---

## Example 5: SQL Injection + Authentication Bypass (Mixed)

```php
<?php
session_start();
$conn = new PDO("mysql:host=localhost;dbname=myapp", "root", "");

// Login form handler - SQL Injection + Auth Bypass combo
$user = $_POST['username'];
$pass = $_POST['password'];

// SQL Injection in authentication query
$sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
$result = $conn->query($sql);
$row = $result->fetch();

// Weak comparison after fetching from DB
if ($row && $row['password'] == $pass) {
    $_SESSION['logged_in'] = true;
    $_SESSION['user'] = $row['username'];
}

// Admin check using cookie (auth bypass)
if (isset($_COOKIE['admin_level']) && $_COOKIE['admin_level'] == '1') {
    $_SESSION['admin'] = true;
}

// Profile update with SQL injection
$new_email = $_REQUEST['email'];
$update = "UPDATE users SET email = '$new_email' WHERE id = " . $_GET['id'];
$conn->query($update);

// strcmp bypass on API key
$api_key = $_GET['key'];
if (strcmp($api_key, $config['api_secret']) == 0) {
    $data = "SELECT * FROM sensitive_data WHERE category = '" . $_GET['cat'] . "'";
    $result = $conn->query($data);
    echo json_encode($result->fetchAll());
}
?>
```

---

## Example 6: SSRF + Input Validation (Mixed)

```php
<?php
// Webhook manager - SSRF and Input Validation vulnerabilities

// SSRF: Fetching user-provided URL
$feed_url = $_POST['feed_url'];
$feed_content = file_get_contents($feed_url);
$xml = simplexml_load_string($feed_content);

// SSRF via curl
$target = $_GET['url'];
$ch = curl_init($target);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
$data = curl_exec($ch);
curl_close($ch);

// Input Validation: Direct echo of user input
$title = $_GET['title'];
echo "<h1>Feed: $title</h1>";
echo "<div>" . $_POST['description'] . "</div>";

// Input Validation: Command injection via hostname
$host = $_REQUEST['hostname'];
system("nslookup " . $host);
exec("dig " . $host, $output);

// Input Validation: eval with user data
$transform = $_POST['transform'];
eval($transform);

// SSRF: Server-side fetch with user path
$path = $_GET['path'];
$internal_data = file_get_contents("http://internal-api:8080/" . $path);
echo $internal_data;

// Input Validation: Unsafe file handling
$report = $_GET['report'];
$content = file_get_contents("reports/" . $report);
header("Content-Type: application/pdf");

// Input Validation: Header injection
$callback = $_POST['callback'];
header("X-Callback: " . $callback);
?>
```

---

## Example 7: Safe Code (Should Score Low/Zero)

```php
<?php
// Secure implementation - should produce minimal or no findings
session_start();
session_regenerate_id(true);

// CSRF token generation and validation
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF validation failed');
    }
}

// Secure database query with prepared statements
$pdo = new PDO("mysql:host=localhost;dbname=app", "user", "pass");
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false) {
    die('Invalid ID');
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bindParam(1, $id, PDO::PARAM_INT);
$stmt->execute();
$user = $stmt->fetch();

// Secure output with htmlspecialchars
$name = htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8');
echo "<p>Welcome, $name</p>";

// Secure password verification
$password = $_POST['password'];
if (password_verify($password, $user['password_hash'])) {
    $_SESSION['authenticated'] = true;
}

// Secure URL validation
$url = filter_var($_POST['website'], FILTER_VALIDATE_URL);
$allowed_hosts = ['example.com', 'trusted-api.com'];
$parsed = parse_url($url);
if ($url && in_array($parsed['host'], $allowed_hosts, true) && $parsed['scheme'] === 'https') {
    $content = file_get_contents($url);
}

// Secure file upload
$allowed_extensions = ['jpg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION));
if (in_array($ext, $allowed_extensions, true)) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $_FILES['photo']['tmp_name']);
    if (strpos($mime, 'image/') === 0) {
        $safe_name = bin2hex(random_bytes(16)) . '.' . $ext;
        move_uploaded_file($_FILES['photo']['tmp_name'], 'uploads/' . $safe_name);
    }
}

// Input validation with filter_var
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
if ($email === false) {
    die('Invalid email');
}

$age = filter_var($_POST['age'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 150]]);
if (is_numeric($age) && ctype_digit((string)$age)) {
    echo "Age: " . intval($age);
}
?>
```
