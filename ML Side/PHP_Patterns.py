#!/usr/bin/env python3
"""
PHP Vulnerability Detection Patterns

Pattern definitions used by the PHPFeatureExtractor and RuleBasedClassifier
to identify vulnerability indicators in PHP code. Each dictionary maps
a descriptive pattern name to a tuple of (regex_string, severity_weight).

Severity weights (0-100) reflect the impact of the pattern:
- 70-90: CRITICAL - Direct exploitation path, immediate risk
- 40-65: HIGH - Highly exploitable, significant risk
- 15-30: MEDIUM - Contributes to risk, context-dependent
- 5-10:  LOW - Indicator only, not directly exploitable

Categories:
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Authentication Bypass
- Input Validation Issues
- Safe Patterns (indicators of secure coding practices)
"""

# SQL Injection indicators
# Format: pattern_name: (regex, severity_weight)
SQL_PATTERNS = {
    'direct_query_concat': (r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\.\s*\$', 80),
    'string_concat_query': (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^;]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)', 85),
    'sql_string_concat_var': (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^;]*\.\s*\$\w+', 75),
    'interpolated_sql_var': (r'["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"\']*\$\w+', 75),
    'no_prepared_stmt': (r'(?:mysql_query|mysqli_query)\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST)', 75),
    'raw_input_sql': (r'(?:WHERE|AND|OR)\s+\w+\s*=\s*[\'"]?\s*\.\s*\$_(?:GET|POST|REQUEST)', 80),
    'order_by_injection': (r'ORDER\s+BY\s+[^;]*\$_(?:GET|POST|REQUEST)', 65),
    'like_injection': (r'LIKE\s+[\'"]%?\s*\.\s*\$_(?:GET|POST|REQUEST)', 60),
    'query_function': (r'(?:mysql_query|mysqli_query|PDO::query|pg_query)', 15),
    'exec_stmt': (r'(?:execute|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST)', 70),
    'sprintf_query': (r'sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)', 55),
    'db_connection': (r'(?:mysqli_connect|mysql_connect|pg_connect|PDO\s*\()', 5),
}

# SSRF (Server-Side Request Forgery) indicators
SSRF_PATTERNS = {
    'curl_user_input': (r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)', 80),
    'file_get_contents_url': (r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)', 85),
    'fopen_url': (r'fopen\s*\(\s*\$_(?:GET|POST|REQUEST)', 75),
    'fsockopen_input': (r'fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST)', 75),
    'curl_exec': (r'curl_exec\s*\(', 15),
    'http_request': (r'(?:http_get|http_post|http_request)\s*\([^)]*\$_(?:GET|POST|REQUEST)', 70),
    'url_param': (r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"](?:url|uri|link|href|src|path|file)', 40),
    'stream_context': (r'stream_context_create\s*\([^)]*\$_(?:GET|POST|REQUEST)', 65),
    'gethostbyname': (r'gethostbyname\s*\(\s*\$_(?:GET|POST|REQUEST)', 60),
    'dns_get_record': (r'dns_get_record\s*\(\s*\$_(?:GET|POST|REQUEST)', 55),
}

# Authentication Bypass indicators
AUTH_BYPASS_PATTERNS = {
    'weak_comparison': (r'if\s*\(\s*\$_(?:GET|POST|REQUEST|SESSION)\s*\[\s*[\'"](?:password|pass|pwd)[\'"]]\s*==\s*', 80),
    'strcmp_bypass': (r'strcmp\s*\(\s*\$_(?:GET|POST|REQUEST)', 75),
    'md5_comparison': (r'md5\s*\(\s*\$_(?:GET|POST|REQUEST)[^)]*\)\s*==', 70),
    'session_fixation': (r'\$_SESSION\s*\[\s*[\'"](?:user|admin|logged|auth)[\'"]]\s*=\s*\$_(?:GET|POST|REQUEST)', 75),
    'cookie_auth': (r'if\s*\(\s*isset\s*\(\s*\$_COOKIE\s*\[\s*[\'"](?:admin|auth|logged)', 65),
    'or_true_login': (r'(?:WHERE|AND)\s+[^;]*(?:=\s*[\'"]?\s*\$_(?:GET|POST|REQUEST)|OR\s+1\s*=\s*1)', 85),
    'type_juggling': (r'==\s*(?:0|false|null|""|\[\])', 25),
    'extract_globals': (r'extract\s*\(\s*\$_(?:GET|POST|REQUEST|GLOBALS)', 85),
    'register_globals': (r'register_globals', 50),
    'unserialize_input': (r'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST)', 80),
}

# Input Validation indicators
INPUT_VALIDATION_PATTERNS = {
    'no_sanitization': (r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\](?!\s*(?:\)|,))', 20),
    'echo_direct': (r'echo\s+\$_(?:GET|POST|REQUEST)', 65),
    'print_direct': (r'print\s+\$_(?:GET|POST|REQUEST)', 65),
    'direct_include': (r'(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)', 80),
    'eval_input': (r'eval\s*\(\s*\$_(?:GET|POST|REQUEST)', 90),
    'preg_replace_e': (r'preg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]', 75),
    'system_exec': (r'(?:system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(?:GET|POST|REQUEST)', 90),
    'assert_input': (r'assert\s*\(\s*\$_(?:GET|POST|REQUEST)', 85),
    'create_function': (r'create_function\s*\([^,]*,\s*\$_(?:GET|POST|REQUEST)', 80),
    'file_upload': (r'\$_FILES\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\[\s*[\'"](?:tmp_name|name)', 35),
    'header_injection': (r'header\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)', 60),
    'mail_injection': (r'mail\s*\([^)]*\$_(?:GET|POST|REQUEST)', 55),
}

# Safe patterns (indicators of secure coding - reduce vulnerability score)
# Weight here represents how much to deduct from vulnerability scores
SAFE_PATTERNS = {
    'prepared_statements': (r'(?:prepare|bindParam|bindValue|execute)\s*\(', 30),
    'htmlspecialchars': (r'htmlspecialchars\s*\(', 20),
    'htmlentities': (r'htmlentities\s*\(', 20),
    'mysqli_real_escape': (r'mysqli_real_escape_string\s*\(', 15),
    'addslashes': (r'addslashes\s*\(', 10),
    'intval': (r'intval\s*\(', 15),
    'filter_input': (r'filter_input\s*\(', 25),
    'filter_var': (r'filter_var\s*\(', 25),
    'preg_match_validation': (r'preg_match\s*\(\s*[\'"][^\'"]*(email|url|phone|digit)', 15),
    'is_numeric': (r'is_numeric\s*\(', 15),
    'ctype_': (r'ctype_\w+\s*\(', 10),
    'password_hash': (r'password_hash\s*\(', 25),
    'password_verify': (r'password_verify\s*\(', 25),
    'csrf_token': (r'(?:csrf|token|nonce)', 10),
    'session_regenerate': (r'session_regenerate_id\s*\(', 20),
}
