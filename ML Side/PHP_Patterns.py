#!/usr/bin/env python3
"""
PHP Vulnerability Detection Patterns

Pattern definitions used by the PHPFeatureExtractor and RuleBasedClassifier
to identify vulnerability indicators in PHP code. Each dictionary maps
a descriptive pattern name to a regex string.

Categories:
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Authentication Bypass
- Input Validation Issues
- Safe Patterns (indicators of secure coding practices)
"""

# SQL Injection indicators
SQL_PATTERNS = {
    'direct_query_concat': r'(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\.\s*\$',
    'string_concat_query': r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^;]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)',
    'no_prepared_stmt': r'(?:mysql_query|mysqli_query)\s*\(\s*["\'][^"\']*\$_(?:GET|POST|REQUEST)',
    'raw_input_sql': r'(?:WHERE|AND|OR)\s+\w+\s*=\s*[\'"]?\s*\.\s*\$_(?:GET|POST|REQUEST)',
    'order_by_injection': r'ORDER\s+BY\s+[^;]*\$_(?:GET|POST|REQUEST)',
    'like_injection': r'LIKE\s+[\'"]%?\s*\.\s*\$_(?:GET|POST|REQUEST)',
    'query_function': r'(?:mysql_query|mysqli_query|PDO::query|pg_query)',
    'exec_stmt': r'(?:execute|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
    'sprintf_query': r'sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',
    'db_connection': r'(?:mysqli_connect|mysql_connect|pg_connect|PDO\s*\()',
}

# SSRF (Server-Side Request Forgery) indicators
SSRF_PATTERNS = {
    'curl_user_input': r'curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)',
    'file_get_contents_url': r'file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'fopen_url': r'fopen\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'fsockopen_input': r'fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'curl_exec': r'curl_exec\s*\(',
    'http_request': r'(?:http_get|http_post|http_request)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
    'url_param': r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"](?:url|uri|link|href|src|path|file)',
    'stream_context': r'stream_context_create\s*\([^)]*\$_(?:GET|POST|REQUEST)',
    'gethostbyname': r'gethostbyname\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'dns_get_record': r'dns_get_record\s*\(\s*\$_(?:GET|POST|REQUEST)',
}

# Authentication Bypass indicators
AUTH_BYPASS_PATTERNS = {
    'weak_comparison': r'if\s*\(\s*\$_(?:GET|POST|REQUEST|SESSION)\s*\[\s*[\'"](?:password|pass|pwd)[\'"]]\s*==\s*',
    'strcmp_bypass': r'strcmp\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'md5_comparison': r'md5\s*\(\s*\$_(?:GET|POST|REQUEST)[^)]*\)\s*==',
    'session_fixation': r'\$_SESSION\s*\[\s*[\'"](?:user|admin|logged|auth)[\'"]]\s*=\s*\$_(?:GET|POST|REQUEST)',
    'cookie_auth': r'if\s*\(\s*isset\s*\(\s*\$_COOKIE\s*\[\s*[\'"](?:admin|auth|logged)',
    'or_true_login': r'(?:WHERE|AND)\s+[^;]*(?:=\s*[\'"]?\s*\$_(?:GET|POST|REQUEST)|OR\s+1\s*=\s*1)',
    'type_juggling': r'==\s*(?:0|false|null|""|\[\])',
    'extract_globals': r'extract\s*\(\s*\$_(?:GET|POST|REQUEST|GLOBALS)',
    'register_globals': r'register_globals',
    'unserialize_input': r'unserialize\s*\(\s*\$_(?:GET|POST|REQUEST)',
}

# Input Validation indicators
INPUT_VALIDATION_PATTERNS = {
    'no_sanitization': r'\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"][^\'"]+[\'"]\s*\](?!\s*(?:\)|,))',
    'echo_direct': r'echo\s+\$_(?:GET|POST|REQUEST)',
    'print_direct': r'print\s+\$_(?:GET|POST|REQUEST)',
    'direct_include': r'(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'eval_input': r'eval\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'preg_replace_e': r'preg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]',
    'system_exec': r'(?:system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'assert_input': r'assert\s*\(\s*\$_(?:GET|POST|REQUEST)',
    'create_function': r'create_function\s*\([^,]*,\s*\$_(?:GET|POST|REQUEST)',
    'file_upload': r'\$_FILES\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\[\s*[\'"](?:tmp_name|name)',
    'header_injection': r'header\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)',
    'mail_injection': r'mail\s*\([^)]*\$_(?:GET|POST|REQUEST)',
}

# Safe patterns (indicators of secure coding - reduce vulnerability score)
SAFE_PATTERNS = {
    'prepared_statements': r'(?:prepare|bindParam|bindValue|execute)\s*\(',
    'htmlspecialchars': r'htmlspecialchars\s*\(',
    'htmlentities': r'htmlentities\s*\(',
    'mysqli_real_escape': r'mysqli_real_escape_string\s*\(',
    'addslashes': r'addslashes\s*\(',
    'intval': r'intval\s*\(',
    'filter_input': r'filter_input\s*\(',
    'filter_var': r'filter_var\s*\(',
    'preg_match_validation': r'preg_match\s*\(\s*[\'"][^\'"]*(email|url|phone|digit)',
    'is_numeric': r'is_numeric\s*\(',
    'ctype_': r'ctype_\w+\s*\(',
    'password_hash': r'password_hash\s*\(',
    'password_verify': r'password_verify\s*\(',
    'csrf_token': r'(?:csrf|token|nonce)',
    'session_regenerate': r'session_regenerate_id\s*\(',
}
