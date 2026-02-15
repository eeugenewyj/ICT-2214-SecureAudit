#!/usr/bin/env python3
"""
Dataset Generator for PHP Vulnerability Classifier

Generates 1000 synthetic PHP code samples for training the ML model.
Each sample includes an impact severity label alongside vulnerability type.

Categories:
- SQL Injection (critical/high impact)
- SSRF (high/critical impact)
- Authentication Bypass (critical/high impact)
- Input Validation Issues (critical/high/medium impact)
- Safe code (no impact)

Impact levels: critical, high, medium, low, safe
"""

import json
import random
import os

# ============================================================
# SQL INJECTION TEMPLATES - organized by impact severity
# ============================================================

SQL_INJECTION_CRITICAL = [
    # Direct concatenation with user input into queries
    '''<?php
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $query);
?>''',
    '''<?php
$username = $_POST['username'];
$sql = "SELECT * FROM accounts WHERE username = '$username'";
$result = mysql_query($sql);
?>''',
    '''<?php
$search = $_REQUEST['q'];
$query = "SELECT title, content FROM articles WHERE title LIKE '%$search%'";
mysqli_query($connection, $query);
?>''',
    '''<?php
$category = $_POST['cat'];
$stmt = "SELECT * FROM items WHERE category = '" . $category . "'";
pg_query($conn, $stmt);
?>''',
    '''<?php
$email = $_GET['email'];
$query = sprintf("SELECT * FROM newsletter WHERE email = '%s'", $email);
mysqli_query($link, $query);
?>''',
    '''<?php
$price = $_REQUEST['max_price'];
$sql = "SELECT * FROM products WHERE price < $price";
$pdo->query($sql);
?>''',
    '''<?php
$table = $_GET['table'];
$query = "SELECT * FROM " . $table . " LIMIT 10";
mysql_query($query);
?>''',
    '''<?php
$id = $_COOKIE['user_id'];
$result = mysqli_query($con, "DELETE FROM sessions WHERE user_id = $id");
?>''',
    '''<?php
$name = $_POST['name'];
$email = $_POST['email'];
$query = "INSERT INTO users (name, email) VALUES ('$name', '$email')";
mysql_query($query);
?>''',
    '''<?php
$old_pass = $_POST['old'];
$new_pass = $_POST['new'];
$user = $_SESSION['user'];
$sql = "UPDATE users SET password = '$new_pass' WHERE username = '$user' AND password = '$old_pass'";
mysqli_query($conn, $sql);
?>''',
    '''<?php
$conditions = $_POST['conditions'];
$sql = "SELECT * FROM inventory WHERE " . $conditions;
mysqli_query($db_conn, $sql);
?>''',
    '''<?php
$user_input = $_POST['custom_query'];
$result = $pdo->query($user_input);
?>''',
    '''<?php
$field = $_REQUEST['field'];
$value = $_REQUEST['value'];
$sql = "SELECT * FROM data WHERE $field = '$value'";
mysqli_query($db, $sql);
?>''',
    '''<?php
$status = $_POST['status'];
$update = "UPDATE orders SET status = '$status' WHERE id = " . $_GET['id'];
$conn->query($update);
?>''',
    '''<?php
$filter = json_decode($_POST['filter'], true);
$where = implode(' AND ', array_map(function($k, $v) { return "$k = '$v'"; }, array_keys($filter), $filter));
$query = "SELECT * FROM records WHERE $where";
$pdo->query($query);
?>''',
    '''<?php
$ids = $_GET['ids'];
$query = "SELECT * FROM products WHERE id IN ($ids)";
mysqli_query($connection, $query);
?>''',
    '''<?php
$join_table = $_GET['related'];
$sql = "SELECT a.*, b.* FROM main a JOIN $join_table b ON a.id = b.main_id";
pg_query($conn, $sql);
?>''',
    '''<?php
$date_from = $_GET['from'];
$date_to = $_GET['to'];
$query = "SELECT * FROM transactions WHERE date BETWEEN '$date_from' AND '$date_to'";
$pdo->exec($query);
?>''',
    '''<?php
$columns = $_POST['cols'];
$sql = "SELECT $columns FROM data_table";
mysqli_query($conn, $sql);
?>''',
    '''<?php
$group = $_REQUEST['group_by'];
$sql = "SELECT COUNT(*), $group FROM stats GROUP BY $group";
$result = mysql_query($sql);
?>''',
]

SQL_INJECTION_HIGH = [
    '''<?php
$order = $_GET['sort'];
$sql = "SELECT * FROM products ORDER BY " . $order;
$db->query($sql);
?>''',
    '''<?php
$keyword = htmlspecialchars($_GET['keyword']);
$sql = "SELECT * FROM posts WHERE body LIKE '%$keyword%'";
mysqli_query($mysqli, $sql);
?>''',
    '''<?php
$limit = $_GET['limit'];
$offset = $_GET['offset'];
$query = "SELECT * FROM logs LIMIT $limit OFFSET $offset";
$pdo->query($query);
?>''',
    '''<?php
$year = $_GET['year'];
$month = $_GET['month'];
$query = "SELECT * FROM events WHERE YEAR(date) = $year AND MONTH(date) = $month";
mysql_query($query, $link);
?>''',
    '''<?php
$regex = $_GET['pattern'];
$sql = "SELECT * FROM logs WHERE message REGEXP '$regex'";
mysqli_query($conn, $sql);
?>''',
    '''<?php
$sort_dir = $_GET['dir'];
$sql = "SELECT * FROM items ORDER BY name " . $sort_dir;
$db->query($sql);
?>''',
    '''<?php
$page_num = $_GET['page'];
$per_page = 10;
$offset = $page_num * $per_page;
$sql = "SELECT * FROM articles LIMIT $per_page OFFSET $offset";
mysqli_query($conn, $sql);
?>''',
    '''<?php
$tag = $_GET['tag'];
$sql = "SELECT p.* FROM posts p JOIN tags t ON p.id = t.post_id WHERE t.name = '$tag'";
$result = $pdo->query($sql);
?>''',
    '''<?php
$min_rating = $_GET['min_rating'];
$sql = "SELECT * FROM reviews WHERE rating >= $min_rating ORDER BY created_at DESC";
$stmt = $db->query($sql);
?>''',
    '''<?php
$search_field = $_POST['search_in'];
$search_value = $_POST['search_for'];
$sql = "SELECT * FROM catalog WHERE $search_field LIKE '%$search_value%'";
pg_query($conn, $sql);
?>''',
]

# ============================================================
# SSRF TEMPLATES - organized by impact severity
# ============================================================

SSRF_CRITICAL = [
    '''<?php
$url = $_GET['url'];
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
echo $response;
?>''',
    '''<?php
$image_url = $_GET['img'];
$content = file_get_contents($image_url);
header('Content-Type: image/jpeg');
echo $content;
?>''',
    '''<?php
$resource = $_REQUEST['resource'];
$data = file_get_contents($resource);
file_put_contents('cache/' . md5($resource), $data);
?>''',
    '''<?php
$metadata_path = $_GET['path'];
$url = "http://169.254.169.254" . $metadata_path;
echo file_get_contents($url);
?>''',
    '''<?php
$endpoint = $_GET['endpoint'];
$response = file_get_contents("http://internal-api/" . $endpoint);
echo $response;
?>''',
    '''<?php
$service = $_POST['service'];
$path = $_POST['path'];
$ch = curl_init("http://$service:8080$path");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
?>''',
    '''<?php
$instance_id = $_REQUEST['id'];
$ch = curl_init("http://metadata.google.internal/computeMetadata/v1/instance/$instance_id");
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Metadata-Flavor: Google']);
echo curl_exec($ch);
?>''',
    '''<?php
$xml_url = $_POST['xml'];
$xml_content = file_get_contents($xml_url);
$doc = new DOMDocument();
$doc->loadXML($xml_content, LIBXML_NOENT);
?>''',
    '''<?php
$file_url = $_GET['file'];
$handle = fopen($file_url, 'r');
$contents = fread($handle, filesize($file_url));
fclose($handle);
?>''',
    '''<?php
$host = $_GET['host'];
$port = $_GET['port'];
$fp = fsockopen($host, $port, $errno, $errstr, 30);
fputs($fp, "GET / HTTP/1.1\r\n\r\n");
echo fgets($fp, 128);
?>''',
    '''<?php
$data = file_get_contents("http://169.254.169.254/latest/meta-data/");
echo $data;
?>''',
    '''<?php
$meta = file_get_contents("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
?>''',
    '''<?php
$ch = curl_init("http://metadata.google.internal/computeMetadata/v1/");
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Metadata-Flavor: Google']);
echo curl_exec($ch);
?>''',
    '''<?php
$admin = file_get_contents("http://localhost/admin");
echo $admin;
?>''',    
    '''<?php
$internal = file_get_contents("http://127.0.0.1:8080/status");
?>''',    
    '''<?php
$data = file_get_contents("http://192.168.1.1/config");
?>''',
    '''<?php
$url = $_GET['url'];
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
echo curl_exec($ch);
?>''',  
    '''<?php
$ch = curl_init($_POST['endpoint']);
curl_setopt_array($ch, [
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_RETURNTRANSFER => true
]);
$response = curl_exec($ch);
?>''',  
    '''<?php
$service = "http://10.0.0.5:9200/_search";
$result = file_get_contents($service);
?>''',  
    '''<?php
$ch = curl_init("http://localhost:6379/");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
?>''',
]

SSRF_HIGH = [
    '''<?php
$target = $_POST['target'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $target);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
$data = curl_exec($ch);
?>''',
    '''<?php
$api_url = $_REQUEST['api'];
$ch = curl_init($api_url);
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_SSL_VERIFYPEER => false]);
$result = curl_exec($ch);
print_r(json_decode($result));
?>''',
    '''<?php
$feed = $_POST['feed_url'];
$xml = file_get_contents($feed);
$rss = simplexml_load_string($xml);
?>''',
    '''<?php
$callback = $_POST['webhook'];
$data = ['status' => 'complete', 'result' => $result];
$ch = curl_init($callback);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_exec($ch);
?>''',
    '''<?php
$notification_url = $_GET['notify'];
$context = stream_context_create(['http' => ['method' => 'POST', 'content' => $payload]]);
file_get_contents($notification_url, false, $context);
?>''',
    '''<?php
$link = $_GET['link'];
$ch = curl_init($link);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 10);
$content = curl_exec($ch);
?>''',
    '''<?php
$redirect_url = $_POST['redirect'];
header("Location: " . $redirect_url);
$page = file_get_contents($redirect_url);
?>''',
    '''<?php
$domain = $_GET['domain'];
$ip = gethostbyname($domain);
$ch = curl_init("http://$ip/");
curl_exec($ch);
?>''',
    '''<?php
$hostname = $_REQUEST['hostname'];
$records = dns_get_record($hostname, DNS_A);
foreach($records as $r) {
    file_get_contents("http://" . $r['ip']);
}
?>''',
    '''<?php
$stream = $_POST['stream'];
$fp = fopen($stream, 'rb');
fpassthru($fp);
?>''',
    '''<?php
$import_url = $_GET['import'];
$csv = file_get_contents($import_url);
$lines = explode("\\n", $csv);
?>''',
    '''<?php
$header_img = $_POST['logo_url'];
$pdf_content = file_get_contents($header_img);
$pdf->Image($header_img, 10, 10, 50);
?>''',
    '''<?php
$avatar = $_REQUEST['avatar_url'];
$img = imagecreatefromjpeg($avatar);
imagejpeg($img, "avatars/" . $_SESSION['user_id'] . ".jpg");
?>''',
    '''<?php
$server = $_POST['server'];
$sock = fsockopen($server, 80);
fwrite($sock, "HEAD / HTTP/1.0\\r\\nHost: $server\\r\\n\\r\\n");
?>''',
]

# ============================================================
# AUTH BYPASS TEMPLATES - organized by impact severity
# ============================================================

AUTH_BYPASS_CRITICAL = [
    '''<?php
$password = $_POST['password'];
$stored = get_password_from_db($username);
if ($password == $stored) {
    $_SESSION['logged_in'] = true;
}
?>''',
    '''<?php
extract($_POST);
if ($authenticated) {
    show_dashboard();
}
?>''',
    '''<?php
extract($_GET);
include $page . '.php';
?>''',
    '''<?php
$user = $_POST['username'];
$pass = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
if (mysqli_num_rows(mysqli_query($conn, $query)) > 0) {
    $_SESSION['authenticated'] = true;
}
?>''',
    '''<?php
$login = $_POST['login'];
$pwd = md5($_POST['pwd']);
$sql = "SELECT id FROM admins WHERE login='$login' AND password='$pwd' OR 1=1";
$result = mysql_query($sql);
?>''',
    '''<?php
$user_data = unserialize($_COOKIE['user']);
if ($user_data['role'] === 'admin') {
    admin_panel();
}
?>''',
    '''<?php
$auth = unserialize(base64_decode($_POST['auth']));
$_SESSION = array_merge($_SESSION, $auth);
?>''',
    '''<?php
$admin_pass = $_POST['password'];
if ($admin_pass == "admin" || $admin_pass == "password123") {
    $_SESSION['admin'] = true;
}
?>''',
    '''<?php
$session_id = $_GET['session'];
session_id($session_id);
session_start();
$_SESSION['user'] = $_POST['username'];
?>''',
    '''<?php
if (isset($_REQUEST['PHPSESSID'])) {
    session_id($_REQUEST['PHPSESSID']);
}
session_start();
?>''',
]

AUTH_BYPASS_HIGH = [
    '''<?php
$pass = $_POST['password'];
$correct = "secretpassword123";
if (strcmp($pass, $correct) == 0) {
    login_user();
}
?>''',
    '''<?php
$api_key = $_GET['key'];
if (strcmp($api_key, $config['api_key']) == 0) {
    return true;
}
?>''',
    '''<?php
$input = $_POST['code'];
if (md5($input) == "0e123456789") {
    bypass_verification();
}
?>''',
    '''<?php
$hash1 = md5($_GET['a']);
$hash2 = md5($_GET['b']);
if ($hash1 == $hash2) {
    grant_access();
}
?>''',
    '''<?php
if (isset($_COOKIE['admin']) && $_COOKIE['admin'] == 'true') {
    show_admin_panel();
}
?>''',
    '''<?php
$role = $_COOKIE['user_role'];
if ($role == 'administrator') {
    include 'admin_functions.php';
}
?>''',
    '''<?php
$token = $_GET['jwt'];
$parts = explode('.', $token);
$payload = json_decode(base64_decode($parts[1]), true);
if ($payload['admin'] == true) {
    grant_admin();
}
?>''',
    '''<?php
$auth_header = $_SERVER['HTTP_AUTHORIZATION'];
if ($auth_header == "Bearer admin") {
    return true;
}
?>''',
    '''<?php
$user_id = $_GET['user_id'];
$profile = get_user_profile($user_id);
echo json_encode($profile);
?>''',
    '''<?php
$doc_id = $_REQUEST['document'];
$content = file_get_contents("documents/$doc_id.pdf");
header('Content-Type: application/pdf');
echo $content;
?>''',
]

AUTH_BYPASS_MEDIUM = [
    '''<?php
$token = $_GET['token'];
if ($token == "0") {
    grant_admin_access();
}
?>''',
    '''<?php
$pin = $_POST['pin'];
if ($pin == 0) {
    authenticate_user();
}
?>''',
    '''<?php
$is_admin = $_POST['admin'];
if ($is_admin == true) {
    $_SESSION['is_admin'] = 1;
}
?>''',
    '''<?php
$count = $_GET['count'];
if ($count == false) {
    skip_limit_check();
}
?>''',
    '''<?php
$otp = $_POST['otp'];
$stored_otp = $_SESSION['otp'];
if ($otp === $stored_otp) {
    unset($_SESSION['otp']);
    authenticate();
}
?>''',
]

# ============================================================
# INPUT VALIDATION TEMPLATES - organized by impact severity
# ============================================================

INPUT_VALIDATION_CRITICAL = [
    '''<?php
$calc = $_GET['expression'];
eval('$result = ' . $calc . ';');
echo $result;
?>''',
    '''<?php
$code = $_POST['code'];
eval($code);
?>''',
    '''<?php
$file = $_GET['filename'];
system("cat " . $file);
?>''',
    '''<?php
$ip = $_POST['ip'];
exec("ping -c 4 " . $ip, $output);
print_r($output);
?>''',
    '''<?php
$cmd = $_REQUEST['cmd'];
$result = shell_exec($cmd);
echo "<pre>$result</pre>";
?>''',
    '''<?php
$host = $_GET['host'];
passthru("nslookup " . $host);
?>''',
    '''<?php
$archive = $_POST['archive'];
$output = `tar -xvf $archive`;
echo $output;
?>''',
    '''<?php
$check = $_GET['check'];
assert($check);
?>''',
    '''<?php
$formula = $_POST['formula'];
$calc = create_function('$x', 'return ' . $formula . ';');
echo $calc(5);
?>''',
    '''<?php
$class = $_GET['handler'];
$obj = new $class();
$obj->run();
?>''',
]

INPUT_VALIDATION_HIGH = [
    '''<?php
$page = $_GET['page'];
include($page . '.php');
?>''',
    '''<?php
$template = $_POST['template'];
require("templates/" . $template);
?>''',
    '''<?php
$lang = $_COOKIE['language'];
include_once("lang/$lang.php");
?>''',
    '''<?php
$pattern = $_GET['pattern'];
$replacement = $_GET['replace'];
$text = $_POST['text'];
echo preg_replace($pattern . 'e', $replacement, $text);
?>''',
    '''<?php
$name = $_GET['name'];
echo "Hello, " . $name;
?>''',
    '''<?php
$comment = $_POST['comment'];
echo "<div class='comment'>$comment</div>";
?>''',
    '''<?php
$title = $_REQUEST['title'];
print "<h1>$title</h1>";
?>''',
    '''<?php
$redirect = $_GET['url'];
header("Location: " . $redirect);
?>''',
    '''<?php
$custom_header = $_POST['header'];
header($custom_header);
?>''',
    '''<?php
$to = $_POST['email'];
$subject = $_POST['subject'];
$message = $_POST['message'];
mail($to, $subject, $message);
?>''',
    '''<?php
$from = $_GET['from'];
$headers = "From: $from\\r\\n";
mail($recipient, $subject, $body, $headers);
?>''',
    '''<?php
$username = $_POST['user'];
$filter = "(uid=$username)";
$result = ldap_search($ldap, $base_dn, $filter);
?>''',
    '''<?php
$user = $_GET['username'];
$xpath = "//users/user[name='$user']";
$result = $xml->xpath($xpath);
?>''',
    '''<?php
$name = $_POST['name'];
$template = "Hello, {{name}}!";
echo str_replace('{{name}}', $name, $template);
eval("echo \\"$template\\";");
?>''',
]

INPUT_VALIDATION_MEDIUM = [
    '''<?php
$filename = $_FILES['upload']['name'];
$tmp = $_FILES['upload']['tmp_name'];
move_uploaded_file($tmp, "uploads/" . $filename);
?>''',
    '''<?php
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$newname = "uploads/" . uniqid() . "." . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $newname);
?>''',
    '''<?php
$file = $_GET['file'];
$content = file_get_contents("files/" . $file);
echo $content;
?>''',
    '''<?php
$doc = $_REQUEST['document'];
readfile("documents/" . $doc);
?>''',
    '''<?php
$data = $_POST['data'];
$obj = unserialize($data);
$obj->process();
?>''',
    '''<?php
$config = $_COOKIE['settings'];
$settings = unserialize(base64_decode($config));
apply_settings($settings);
?>''',
]

# ============================================================
# SAFE CODE TEMPLATES
# ============================================================

SAFE_CODE_TEMPLATES = [
    '''<?php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
$user = $stmt->fetch();
?>''',
    '''<?php
$username = htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8');
$password = $_POST['password'];
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
if (password_verify($password, $stored_hash)) {
    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
}
?>''',
    '''<?php
$email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
if ($email === false) {
    die("Invalid email");
}
$stmt = $pdo->prepare("INSERT INTO subscribers (email) VALUES (?)");
$stmt->execute([$email]);
?>''',
    '''<?php
$allowed_pages = ['home', 'about', 'contact', 'products'];
$page = $_GET['page'] ?? 'home';
if (in_array($page, $allowed_pages, true)) {
    include("pages/{$page}.php");
} else {
    include("pages/404.php");
}
?>''',
    '''<?php
$url = filter_var($_POST['url'], FILTER_VALIDATE_URL);
$parsed = parse_url($url);
$allowed_hosts = ['api.example.com', 'cdn.example.com'];
if ($url && in_array($parsed['host'], $allowed_hosts, true)) {
    $content = file_get_contents($url);
}
?>''',
    '''<?php
$password = $_POST['password'];
$hash = password_hash($password, PASSWORD_ARGON2ID);
$stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
$stmt->execute([$hash, $_SESSION['user_id']]);
?>''',
    '''<?php
$search = preg_replace('/[^a-zA-Z0-9\\s]/', '', $_GET['q']);
$stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE ?");
$stmt->execute(['%' . $search . '%']);
?>''',
    '''<?php
$filename = basename($_FILES['upload']['name']);
$allowed_ext = ['jpg', 'png', 'gif'];
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (in_array($ext, $allowed_ext, true)) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
    if (strpos($mime, 'image/') === 0) {
        move_uploaded_file($_FILES['upload']['tmp_name'], 'uploads/' . uniqid() . '.' . $ext);
    }
}
?>''',
    '''<?php
$redirect = $_GET['redirect'] ?? '/';
$allowed_paths = ['/dashboard', '/profile', '/settings'];
if (in_array($redirect, $allowed_paths, true)) {
    header('Location: ' . $redirect);
} else {
    header('Location: /');
}
exit;
?>''',
    '''<?php
$token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $token;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('CSRF validation failed');
    }
}
?>''',
    '''<?php
$user_id = intval($_GET['id']);
if ($user_id <= 0) {
    http_response_code(400);
    die("Invalid user ID");
}
$stmt = $pdo->prepare("SELECT name, email FROM users WHERE id = ? AND active = 1");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
echo htmlspecialchars(json_encode($user), ENT_QUOTES, 'UTF-8');
?>''',
    '''<?php
$comment = trim($_POST['comment']);
if (strlen($comment) > 500) {
    die("Comment too long");
}
$clean_comment = htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
$stmt = $pdo->prepare("INSERT INTO comments (user_id, body, created_at) VALUES (?, ?, NOW())");
$stmt->execute([$_SESSION['user_id'], $clean_comment]);
?>''',
    '''<?php
$ip_address = filter_var($_POST['ip'], FILTER_VALIDATE_IP);
if ($ip_address === false) {
    die("Invalid IP address");
}
$stmt = $pdo->prepare("INSERT INTO allowed_ips (ip) VALUES (?)");
$stmt->execute([$ip_address]);
?>''',
    '''<?php
$page = intval($_GET['page'] ?? 1);
$per_page = 20;
$offset = max(0, ($page - 1) * $per_page);
$stmt = $pdo->prepare("SELECT * FROM articles ORDER BY created_at DESC LIMIT ? OFFSET ?");
$stmt->execute([$per_page, $offset]);
$articles = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>''',
    '''<?php
$allowed_sort = ['name', 'price', 'rating', 'created_at'];
$sort = in_array($_GET['sort'] ?? '', $allowed_sort, true) ? $_GET['sort'] : 'name';
$dir = ($_GET['dir'] ?? 'ASC') === 'DESC' ? 'DESC' : 'ASC';
$stmt = $pdo->prepare("SELECT * FROM products ORDER BY $sort $dir LIMIT 50");
$stmt->execute();
?>''',
]


def generate_variations(template, category):
    """Generate variations of a template with random modifications."""
    variations = [template]

    superglobals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']

    for _ in range(2):
        var = template
        for sg in superglobals:
            if sg in var:
                var = var.replace(sg, random.choice(superglobals), 1)
        variations.append(var)

    return variations


def generate_dataset(num_samples=1000, output_file='vulnerability_dataset.json'):
    """Generate the complete dataset with impact severity labels."""
    dataset = []
    sample_id = 0

    # Template groups: (templates, category, impact)
    template_groups = [
        (SQL_INJECTION_CRITICAL, 'sql_injection', 'critical'),
        (SQL_INJECTION_HIGH, 'sql_injection', 'high'),
        (SSRF_CRITICAL, 'ssrf', 'critical'),
        (SSRF_HIGH, 'ssrf', 'high'),
        (AUTH_BYPASS_CRITICAL, 'authentication_bypass', 'critical'),
        (AUTH_BYPASS_HIGH, 'authentication_bypass', 'high'),
        (AUTH_BYPASS_MEDIUM, 'authentication_bypass', 'medium'),
        (INPUT_VALIDATION_CRITICAL, 'input_validation', 'critical'),
        (INPUT_VALIDATION_HIGH, 'input_validation', 'high'),
        (INPUT_VALIDATION_MEDIUM, 'input_validation', 'medium'),
    ]

    # Calculate distribution: ~16% safe, rest split among vuln groups weighted by template count
    safe_count = num_samples // 6
    vuln_count = num_samples - safe_count

    # Weight vulnerable samples proportionally to template count
    total_templates = sum(len(t) for t, _, _ in template_groups)
    group_targets = []
    allocated = 0
    for i, (templates, cat, impact) in enumerate(template_groups):
        if i == len(template_groups) - 1:
            target = vuln_count - allocated
        else:
            target = max(1, int(vuln_count * len(templates) / total_templates))
        group_targets.append(target)
        allocated += target

    # Generate vulnerable samples per group
    for (templates, category, impact), target_count in zip(template_groups, group_targets):
        generated = 0
        template_idx = 0

        while generated < target_count:
            template = templates[template_idx % len(templates)]
            variations = generate_variations(template, category)

            for var in variations:
                if generated >= target_count:
                    break

                dataset.append({
                    'id': sample_id,
                    'code': var.strip(),
                    'category': category,
                    'is_vulnerable': True,
                    'impact': impact,
                    'labels': {
                        'sql_injection': 1 if category == 'sql_injection' else 0,
                        'ssrf': 1 if category == 'ssrf' else 0,
                        'authentication_bypass': 1 if category == 'authentication_bypass' else 0,
                        'input_validation': 1 if category == 'input_validation' else 0
                    }
                })
                sample_id += 1
                generated += 1

            template_idx += 1

    # Generate safe samples
    generated_safe = 0
    safe_idx = 0
    while generated_safe < safe_count:
        template = SAFE_CODE_TEMPLATES[safe_idx % len(SAFE_CODE_TEMPLATES)]

        dataset.append({
            'id': sample_id,
            'code': template.strip(),
            'category': 'safe',
            'is_vulnerable': False,
            'impact': 'safe',
            'labels': {
                'sql_injection': 0,
                'ssrf': 0,
                'authentication_bypass': 0,
                'input_validation': 0
            }
        })
        sample_id += 1
        generated_safe += 1
        safe_idx += 1

    # Shuffle the dataset
    random.shuffle(dataset)

    # Save to file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"Generated {len(dataset)} samples")
    print(f"Dataset saved to {output_file}")

    # Print statistics
    cat_stats = {}
    impact_stats = {}
    for sample in dataset:
        cat = sample['category']
        imp = sample['impact']
        cat_stats[cat] = cat_stats.get(cat, 0) + 1
        impact_stats[imp] = impact_stats.get(imp, 0) + 1

    print("\nCategory distribution:")
    for cat, count in sorted(cat_stats.items()):
        print(f"  {cat}: {count}")

    print("\nImpact distribution:")
    for imp, count in sorted(impact_stats.items()):
        print(f"  {imp}: {count}")

    return dataset


if __name__ == '__main__':
    output_path = os.path.join(os.path.dirname(__file__), 'data', 'vulnerability_dataset.json')
    generate_dataset(1000, output_path)
