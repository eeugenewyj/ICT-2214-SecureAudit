#!/usr/bin/env python3
"""
Dataset Generator for PHP Vulnerability Classifier

Generates 500+ synthetic PHP code samples for training the ML model.
Categories:
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Authentication Bypass
- Input Validation Issues
"""

import json
import random
import os

# Templates for generating vulnerable PHP code samples

SQL_INJECTION_TEMPLATES = [
    # Direct concatenation patterns
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
$order = $_GET['sort'];
$sql = "SELECT * FROM products ORDER BY " . $order;
$db->query($sql);
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
$columns = $_POST['cols'];
$sql = "SELECT $columns FROM data_table";
mysqli_query($conn, $sql);
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
$limit = $_GET['limit'];
$offset = $_GET['offset'];
$query = "SELECT * FROM logs LIMIT $limit OFFSET $offset";
$pdo->query($query);
?>''',
    '''<?php
$field = $_REQUEST['field'];
$value = $_REQUEST['value'];
$sql = "SELECT * FROM data WHERE $field = '$value'";
mysqli_query($db, $sql);
?>''',
    '''<?php
$year = $_GET['year'];
$month = $_GET['month'];
$query = "SELECT * FROM events WHERE YEAR(date) = $year AND MONTH(date) = $month";
mysql_query($query, $link);
?>''',
    '''<?php
$status = $_POST['status'];
$update = "UPDATE orders SET status = '$status' WHERE id = " . $_GET['id'];
$conn->query($update);
?>''',
    '''<?php
$keyword = htmlspecialchars($_GET['keyword']);
$sql = "SELECT * FROM posts WHERE body LIKE '%$keyword%'";
mysqli_query($mysqli, $sql);
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
$group = $_REQUEST['group_by'];
$sql = "SELECT COUNT(*), $group FROM stats GROUP BY $group";
$result = mysql_query($sql);
?>''',
    '''<?php
$join_table = $_GET['related'];
$sql = "SELECT a.*, b.* FROM main a JOIN $join_table b ON a.id = b.main_id";
pg_query($conn, $sql);
?>''',
    '''<?php
$conditions = $_POST['conditions'];
$sql = "SELECT * FROM inventory WHERE " . $conditions;
mysqli_query($db_conn, $sql);
?>''',
    '''<?php
$date_from = $_GET['from'];
$date_to = $_GET['to'];
$query = "SELECT * FROM transactions WHERE date BETWEEN '$date_from' AND '$date_to'";
$pdo->exec($query);
?>''',
    '''<?php
$user_input = $_POST['custom_query'];
$result = $pdo->query($user_input);
?>''',
    '''<?php
$regex = $_GET['pattern'];
$sql = "SELECT * FROM logs WHERE message REGEXP '$regex'";
mysqli_query($conn, $sql);
?>''',
]

SSRF_TEMPLATES = [
    # curl-based SSRF
    '''<?php
$url = $_GET['url'];
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
echo $response;
?>''',
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
    # file_get_contents SSRF
    '''<?php
$image_url = $_GET['img'];
$content = file_get_contents($image_url);
header('Content-Type: image/jpeg');
echo $content;
?>''',
    '''<?php
$feed = $_POST['feed_url'];
$xml = file_get_contents($feed);
$rss = simplexml_load_string($xml);
?>''',
    '''<?php
$resource = $_REQUEST['resource'];
$data = file_get_contents($resource);
file_put_contents('cache/' . md5($resource), $data);
?>''',
    # fopen SSRF
    '''<?php
$file_url = $_GET['file'];
$handle = fopen($file_url, 'r');
$contents = fread($handle, filesize($file_url));
fclose($handle);
?>''',
    '''<?php
$stream = $_POST['stream'];
$fp = fopen($stream, 'rb');
fpassthru($fp);
?>''',
    # fsockopen SSRF
    '''<?php
$host = $_GET['host'];
$port = $_GET['port'];
$fp = fsockopen($host, $port, $errno, $errstr, 30);
fputs($fp, "GET / HTTP/1.1\r\n\r\n");
echo fgets($fp, 128);
?>''',
    '''<?php
$server = $_POST['server'];
$sock = fsockopen($server, 80);
fwrite($sock, "HEAD / HTTP/1.0\r\nHost: $server\r\n\r\n");
?>''',
    # DNS/IP based SSRF
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
    # Webhook/callback SSRF
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
    # XML External Entity leading to SSRF
    '''<?php
$xml_url = $_POST['xml'];
$xml_content = file_get_contents($xml_url);
$doc = new DOMDocument();
$doc->loadXML($xml_content, LIBXML_NOENT);
?>''',
    '''<?php
$import_url = $_GET['import'];
$csv = file_get_contents($import_url);
$lines = explode("\n", $csv);
?>''',
    # PDF/Image generation SSRF
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
    # API proxy SSRF
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
    # SSRF via redirects
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
    # Cloud metadata SSRF patterns
    '''<?php
$metadata_path = $_GET['path'];
$url = "http://169.254.169.254" . $metadata_path;
echo file_get_contents($url);
?>''',
    '''<?php
$instance_id = $_REQUEST['id'];
$ch = curl_init("http://metadata.google.internal/computeMetadata/v1/instance/$instance_id");
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Metadata-Flavor: Google']);
echo curl_exec($ch);
?>''',
]

AUTH_BYPASS_TEMPLATES = [
    # Weak comparison operators
    '''<?php
$password = $_POST['password'];
$stored = get_password_from_db($username);
if ($password == $stored) {
    $_SESSION['logged_in'] = true;
}
?>''',
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
    # strcmp bypass
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
    # MD5 comparison bypass
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
    # Session fixation
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
    # Cookie-based auth bypass
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
    # Type juggling
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
    # extract() vulnerability
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
    # Unserialize auth bypass
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
    # SQL-based auth bypass
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
    # JWT/Token bypass
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
    # Insecure direct object reference
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
    # Race condition auth
    '''<?php
$otp = $_POST['otp'];
$stored_otp = $_SESSION['otp'];
if ($otp === $stored_otp) {
    unset($_SESSION['otp']);
    authenticate();
}
?>''',
    # Default credentials
    '''<?php
$admin_pass = $_POST['password'];
if ($admin_pass == "admin" || $admin_pass == "password123") {
    $_SESSION['admin'] = true;
}
?>''',
]

INPUT_VALIDATION_TEMPLATES = [
    # Direct echo without sanitization
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
    # Include/require injection
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
    # eval injection
    '''<?php
$calc = $_GET['expression'];
eval('$result = ' . $calc . ';');
echo $result;
?>''',
    '''<?php
$code = $_POST['code'];
eval($code);
?>''',
    # Command injection
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
    # preg_replace code execution
    '''<?php
$pattern = $_GET['pattern'];
$replacement = $_GET['replace'];
$text = $_POST['text'];
echo preg_replace($pattern . 'e', $replacement, $text);
?>''',
    # File upload vulnerabilities
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
    # Header injection
    '''<?php
$redirect = $_GET['url'];
header("Location: " . $redirect);
?>''',
    '''<?php
$custom_header = $_POST['header'];
header($custom_header);
?>''',
    # Mail injection
    '''<?php
$to = $_POST['email'];
$subject = $_POST['subject'];
$message = $_POST['message'];
mail($to, $subject, $message);
?>''',
    '''<?php
$from = $_GET['from'];
$headers = "From: $from\r\n";
mail($recipient, $subject, $body, $headers);
?>''',
    # Path traversal
    '''<?php
$file = $_GET['file'];
$content = file_get_contents("files/" . $file);
echo $content;
?>''',
    '''<?php
$doc = $_REQUEST['document'];
readfile("documents/" . $doc);
?>''',
    # Unsafe deserialization
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
    # assert() injection
    '''<?php
$check = $_GET['check'];
assert($check);
?>''',
    # create_function injection
    '''<?php
$formula = $_POST['formula'];
$calc = create_function('$x', 'return ' . $formula . ';');
echo $calc(5);
?>''',
    # LDAP injection
    '''<?php
$username = $_POST['user'];
$filter = "(uid=$username)";
$result = ldap_search($ldap, $base_dn, $filter);
?>''',
    # XPath injection
    '''<?php
$user = $_GET['username'];
$xpath = "//users/user[name='$user']";
$result = $xml->xpath($xpath);
?>''',
    # Template injection
    '''<?php
$name = $_POST['name'];
$template = "Hello, {{name}}!";
echo str_replace('{{name}}', $name, $template);
eval("echo \"$template\";");
?>''',
    # Object instantiation
    '''<?php
$class = $_GET['handler'];
$obj = new $class();
$obj->run();
?>''',
]

# Safe code templates (for negative samples)
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
$search = preg_replace('/[^a-zA-Z0-9\s]/', '', $_GET['q']);
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
]


def generate_variations(template, category):
    """Generate variations of a template with random modifications."""
    variations = [template]

    # Variable name variations
    var_names = ['input', 'data', 'value', 'param', 'arg', 'user_input', 'request_data']
    superglobals = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE']

    for _ in range(2):
        var = template
        for sg in superglobals:
            if sg in var:
                var = var.replace(sg, random.choice(superglobals), 1)
        variations.append(var)

    return variations


def generate_dataset(num_samples=500, output_file='vulnerability_dataset.json'):
    """Generate the complete dataset."""
    dataset = []
    sample_id = 0

    templates_by_category = {
        'sql_injection': SQL_INJECTION_TEMPLATES,
        'ssrf': SSRF_TEMPLATES,
        'authentication_bypass': AUTH_BYPASS_TEMPLATES,
        'input_validation': INPUT_VALIDATION_TEMPLATES
    }

    samples_per_category = num_samples // 5  # 4 vuln categories + 1 safe
    extra_samples = num_samples - (samples_per_category * 5)

    # Generate vulnerable samples
    for category, templates in templates_by_category.items():
        generated = 0
        template_idx = 0

        while generated < samples_per_category:
            template = templates[template_idx % len(templates)]
            variations = generate_variations(template, category)

            for var in variations:
                if generated >= samples_per_category:
                    break

                dataset.append({
                    'id': sample_id,
                    'code': var.strip(),
                    'category': category,
                    'is_vulnerable': True,
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
    while generated_safe < samples_per_category + extra_samples:
        template = SAFE_CODE_TEMPLATES[safe_idx % len(SAFE_CODE_TEMPLATES)]

        dataset.append({
            'id': sample_id,
            'code': template.strip(),
            'category': 'safe',
            'is_vulnerable': False,
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
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"Generated {len(dataset)} samples")
    print(f"Dataset saved to {output_file}")

    # Print statistics
    stats = {}
    for sample in dataset:
        cat = sample['category']
        stats[cat] = stats.get(cat, 0) + 1

    print("\nCategory distribution:")
    for cat, count in sorted(stats.items()):
        print(f"  {cat}: {count}")

    return dataset


if __name__ == '__main__':
    output_path = os.path.join(os.path.dirname(__file__), 'data', 'vulnerability_dataset.json')
    generate_dataset(500, output_path)
