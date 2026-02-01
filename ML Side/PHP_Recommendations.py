#!/usr/bin/env python3
"""
PHP Vulnerability Remediation Recommendations

Contains recommendation data for each vulnerability category.
Each entry includes severity, remediation steps, and
secure vs vulnerable code examples conforming to OWASP standards.
"""


def generate_recommendations(results):
    """Generate remediation recommendations based on analysis findings.

    Args:
        results: Dictionary containing analysis results with confidence
                 scores for each vulnerability type.

    Returns:
        List of recommendation dictionaries for vulnerabilities
        where confidence > 0.
    """
    recommendations = []

    if results['sql_injection']['confidence'] > 0:
        recommendations.append({
            'vulnerability': 'SQL Injection',
            'severity': 'CRITICAL',
            'recommendations': [
                'Use prepared statements with parameterized queries',
                'Use PDO or mysqli with bound parameters',
                'Implement input validation and sanitization',
                'Apply the principle of least privilege for database accounts',
                'Use ORM frameworks that handle SQL safely'
            ],
            'example': '''
// Vulnerable:
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// Secure:
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
'''
        })

    if results['ssrf']['confidence'] > 0:
        recommendations.append({
            'vulnerability': 'Server-Side Request Forgery (SSRF)',
            'severity': 'HIGH',
            'recommendations': [
                'Whitelist allowed domains and protocols',
                'Validate and sanitize all URL inputs',
                'Block requests to internal IP ranges (127.0.0.1, 10.x.x.x, 192.168.x.x)',
                'Disable unnecessary URL schemes (file://, gopher://, dict://)',
                'Implement network segmentation'
            ],
            'example': '''
// Vulnerable:
$content = file_get_contents($_GET['url']);

// Secure:
$allowed_hosts = ['api.example.com', 'cdn.example.com'];
$parsed = parse_url($_GET['url']);
if (in_array($parsed['host'], $allowed_hosts) && $parsed['scheme'] === 'https') {
    $content = file_get_contents($_GET['url']);
}
'''
        })

    if results['authentication_bypass']['confidence'] > 0:
        recommendations.append({
            'vulnerability': 'Authentication Bypass',
            'severity': 'CRITICAL',
            'recommendations': [
                'Use strict comparison operators (=== instead of ==)',
                'Implement proper password hashing with password_hash()',
                'Use password_verify() for password comparison',
                'Regenerate session IDs after authentication',
                'Implement multi-factor authentication',
                'Avoid type juggling vulnerabilities'
            ],
            'example': '''
// Vulnerable:
if ($_POST['password'] == $stored_password) { }
if (strcmp($_POST['password'], $stored_password) == 0) { }

// Secure:
$hashed = password_hash($password, PASSWORD_DEFAULT);
if (password_verify($_POST['password'], $stored_hash)) {
    session_regenerate_id(true);
}
'''
        })

    if results['input_validation']['confidence'] > 0:
        recommendations.append({
            'vulnerability': 'Input Validation Issues',
            'severity': 'HIGH',
            'recommendations': [
                'Validate all user inputs against expected formats',
                'Use filter_input() and filter_var() for sanitization',
                'Encode output with htmlspecialchars() to prevent XSS',
                'Never use user input directly in system commands',
                'Implement Content Security Policy headers',
                'Use parameterized file operations'
            ],
            'example': '''
// Vulnerable:
echo $_GET['name'];
include($_GET['page'] . '.php');

// Secure:
$name = htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
echo $name;

$allowed_pages = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed_pages)) {
    include($_GET['page'] . '.php');
}
'''
        })

    return recommendations
