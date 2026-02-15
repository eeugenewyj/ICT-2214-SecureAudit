from .pattern_class import Pattern

PATTERNS = [

# ============================================================
# SQL INJECTION – CWE-89 – OWASP A03:2021 Injection
# ============================================================

Pattern(
    name="direct_query_concat",
    vuln_type="sql_injection",
    regex=r"(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\([^)]*\.\s*\$",
    weight=80,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Use Prepared Statements",
        "description": "Avoid concatenating variables directly into SQL queries.",
        "secure_example": """
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
"""
    }
),

Pattern(
    name="string_concat_query",
    vuln_type="sql_injection",
    regex=r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^;]*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)",
    weight=85,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Prevent SQL Concatenation with Superglobals",
        "description": "Never append raw user input directly into SQL statements.",
        "secure_example": "Use PDO prepared statements with bound parameters."
    }
),

Pattern(
    name="sql_string_concat_var",
    vuln_type="sql_injection",
    regex=r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^;]*\.\s*\$\w+",
    weight=75,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Avoid Variable-Based Query Construction",
        "description": "Validate and parameterize variables before using in queries.",
        "secure_example": "Use placeholders instead of variables in SQL."
    }
),

Pattern(
    name="interpolated_sql_var",
    vuln_type="sql_injection",
    regex=r"[\"'](?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^\"']*\$\w+",
    weight=75,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Avoid SQL String Interpolation",
        "description": "Do not embed PHP variables directly inside SQL strings.",
        "secure_example": "Use prepared statements."
    }
),

Pattern(
    name="no_prepared_stmt",
    vuln_type="sql_injection",
    regex=r"(?:mysql_query|mysqli_query)\s*\(\s*[\"'][^\"']*\$_(?:GET|POST|REQUEST)",
    weight=75,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Replace Raw Queries",
        "description": "Switch to parameterized queries instead of mysql_query().",
        "secure_example": "Use $stmt = $conn->prepare(...);"
    }
),

Pattern(
    name="raw_input_sql",
    vuln_type="sql_injection",
    regex=r"(?:WHERE|AND|OR)\s+\w+\s*=\s*[\'\"]?\s*\.\s*\$_(?:GET|POST|REQUEST)",
    weight=80,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Sanitize WHERE Clause Input",
        "description": "User input in WHERE clauses must be parameterized.",
        "secure_example": "Bind input values using prepared statements."
    }
),

Pattern(
    name="order_by_injection",
    vuln_type="sql_injection",
    regex=r"ORDER\s+BY\s+[^;]*\$_(?:GET|POST|REQUEST)",
    weight=65,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Whitelist ORDER BY Parameters",
        "description": "Restrict ORDER BY inputs to known column names.",
        "secure_example": "if (!in_array($sort, $allowed)) { $sort = 'id'; }"
    }
),

Pattern(
    name="like_injection",
    vuln_type="sql_injection",
    regex=r"LIKE\s+[\'\"]%?\s*\.\s*\$_(?:GET|POST|REQUEST)",
    weight=60,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Sanitize LIKE Queries",
        "description": "Escape wildcard characters and use prepared statements.",
        "secure_example": "Use $stmt->execute(['%'.$search.'%']);"
    }
),

Pattern(
    name="query_function",
    vuln_type="sql_injection",
    regex=r"(?:mysql_query|mysqli_query|PDO::query|pg_query)",
    weight=15,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P3",
    remediation={
        "title": "Use Safe DB APIs",
        "description": "Prefer prepared statements over raw query execution."
    }
),

Pattern(
    name="exec_stmt",
    vuln_type="sql_injection",
    regex=r"(?:execute|exec)\s*\([^)]*\$_(?:GET|POST|REQUEST)",
    weight=70,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Validate Parameters Before Execution",
        "description": "Ensure execute() does not receive raw superglobals."
    }
),

Pattern(
    name="sprintf_query",
    vuln_type="sql_injection",
    regex=r"sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)",
    weight=55,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Avoid sprintf for SQL",
        "description": "Do not format SQL strings with sprintf()."
    }
),

Pattern(
    name="db_connection",
    vuln_type="sql_injection",
    regex=r"(?:mysqli_connect|mysql_connect|pg_connect|PDO\s*\()",
    weight=5,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P4",
    remediation={
        "title": "Secure DB Connections",
        "description": "Ensure connections use least privilege credentials."
    }
),

# ============================================================
# SSRF – CWE-918 – OWASP A10:2021 SSRF
# ============================================================

Pattern(
    name="curl_user_input",
    vuln_type="ssrf",
    regex=r"curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(?:GET|POST|REQUEST)",
    weight=80,
    cwe="CWE-918",
    owasp="A10:2021 - Server-Side Request Forgery",
    fix_priority="P1",
    remediation={
        "title": "Validate cURL URL Input",
        "description": "Whitelist domains and restrict internal IP access.",
        "secure_example": "Validate host with parse_url() before curl_exec()."
    }
),

Pattern(
    name="file_get_contents_url",
    vuln_type="ssrf",
    regex=r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=85,
    cwe="CWE-918",
    owasp="A10:2021 - Server-Side Request Forgery",
    fix_priority="P1",
    remediation={
        "title": "Restrict Remote File Access",
        "description": "Validate and whitelist external URLs.",
        "secure_example": "Use strict hostname validation."
    }
),

# ============================================================
# SSRF
# ============================================================

Pattern(
    name="fopen_url",
    vuln_type="ssrf",
    regex=r"fopen\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=75,
    cwe="CWE-918",
    owasp="A10:2021 - Server-Side Request Forgery",
    fix_priority="P1",
    remediation={
        "title": "Restrict fopen Remote Usage",
        "description": "Prevent fopen() from accessing user-controlled URLs.",
        "secure_example": "Disable allow_url_fopen or validate input."
    }
),

Pattern(
    name="fsockopen_input",
    vuln_type="ssrf",
    regex=r"fsockopen\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=75,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Validate Socket Destinations",
        "description": "Prevent arbitrary outbound socket connections."
    }
),

Pattern(
    name="curl_exec",
    vuln_type="ssrf",
    regex=r"curl_exec\s*\(",
    weight=15,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P3",
    remediation={
        "title": "Audit curl_exec Usage",
        "description": "Ensure URLs passed to curl_exec are validated."
    }
),

Pattern(
    name="http_request",
    vuln_type="ssrf",
    regex=r"(?:http_get|http_post|http_request)\s*\([^)]*\$_(?:GET|POST|REQUEST)",
    weight=70,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Restrict HTTP Client Usage",
        "description": "Whitelist external API endpoints."
    }
),

Pattern(
    name="url_param",
    vuln_type="ssrf",
    regex=r"\$_(?:GET|POST|REQUEST)\s*\[\s*[\'\"](?:url|uri|link|href|src|path|file)",
    weight=40,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P2",
    remediation={
        "title": "Validate URL Parameters",
        "description": "Restrict allowed protocols and domains."
    }
),

Pattern(
    name="stream_context",
    vuln_type="ssrf",
    regex=r"stream_context_create\s*\([^)]*\$_(?:GET|POST|REQUEST)",
    weight=65,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P2",
    remediation={
        "title": "Sanitize Stream Context Input",
        "description": "Validate stream context options."
    }
),

Pattern(
    name="gethostbyname",
    vuln_type="ssrf",
    regex=r"gethostbyname\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=60,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P2",
    remediation={
        "title": "Restrict DNS Resolution",
        "description": "Prevent resolving attacker-controlled domains."
    }
),

Pattern(
    name="dns_get_record",
    vuln_type="ssrf",
    regex=r"dns_get_record\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=55,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P2",
    remediation={
        "title": "Validate DNS Inputs",
        "description": "Ensure hostname input is validated."
    }
),

Pattern(
    name="metadata_endpoint",
    vuln_type="ssrf",
    regex=r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200",
    weight=90,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Block Cloud Metadata Access",
        "description": "Prevent access to cloud instance metadata endpoints."
    }
),

Pattern(
    name="localhost_access",
    vuln_type="ssrf",
    regex=r"(?:file_get_contents|curl_init|fopen)\s*\(\s*[\'\"]https?://(?:localhost|127\.0\.0\.1)",
    weight=80,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Prevent Localhost Access",
        "description": "Disallow requests to internal loopback addresses."
    }
),

Pattern(
    name="follow_redirects",
    vuln_type="ssrf",
    regex=r"CURLOPT_FOLLOWLOCATION\s*,\s*true",
    weight=55,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P2",
    remediation={
        "title": "Disable Follow Redirects",
        "description": "Disable automatic redirects for untrusted URLs."
    }
),

Pattern(
    name="internal_ip_ranges",
    vuln_type="ssrf",
    regex=r"(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)",
    weight=70,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Block Private IP Ranges",
        "description": "Prevent requests to internal private networks."
    }
),

Pattern(
    name="cloud_metadata",
    vuln_type="ssrf",
    regex=r"(?:metadata|instance-data)\.(?:google|amazonaws|azure|digitalocean)",
    weight=85,
    cwe="CWE-918",
    owasp="A10:2021 - SSRF",
    fix_priority="P1",
    remediation={
        "title": "Restrict Cloud Metadata Domains",
        "description": "Block cloud metadata service hostnames."
    }
),

# ============================================================
# AUTHENTICATION BYPASS
# ============================================================

Pattern(
    name="weak_comparison",
    vuln_type="authentication_bypass",
    regex=r"if\s*\(\s*\$_(?:GET|POST|REQUEST|SESSION)\s*\[\s*[\'\"](?:password|pass|pwd)[\'\"]]\s*==\s*",
    weight=80,
    cwe="CWE-287",
    owasp="A07:2021 - Authentication Failures",
    fix_priority="P1",
    remediation={
        "title": "Use Strict Comparison",
        "description": "Replace == with === to prevent type juggling attacks."
    }
),

Pattern(
    name="strcmp_bypass",
    vuln_type="authentication_bypass",
    regex=r"strcmp\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=75,
    cwe="CWE-287",
    owasp="A07:2021 - Authentication Failures",
    fix_priority="P1",
    remediation={
        "title": "Avoid strcmp for Authentication",
        "description": "Use password_verify() instead of strcmp()."
    }
),

Pattern(
    name="md5_comparison",
    vuln_type="authentication_bypass",
    regex=r"md5\s*\(\s*\$_(?:GET|POST|REQUEST)[^)]*\)\s*==",
    weight=70,
    cwe="CWE-327",
    owasp="A02:2021 - Cryptographic Failures",
    fix_priority="P1",
    remediation={
        "title": "Replace MD5 Hashing",
        "description": "Use password_hash() and password_verify()."
    }
),

Pattern(
    name="session_fixation",
    vuln_type="authentication_bypass",
    regex=r"\$_SESSION\s*\[\s*[\'\"](?:user|admin|logged|auth)[\'\"]]\s*=\s*\$_(?:GET|POST|REQUEST)",
    weight=75,
    cwe="CWE-384",
    owasp="A07:2021 - Authentication Failures",
    fix_priority="P1",
    remediation={
        "title": "Prevent Session Fixation",
        "description": "Regenerate session ID after login."
    }
),

Pattern(
    name="cookie_auth",
    vuln_type="authentication_bypass",
    regex=r"if\s*\(\s*isset\s*\(\s*\$_COOKIE\s*\[\s*[\'\"](?:admin|auth|logged)",
    weight=65,
    cwe="CWE-287",
    owasp="A07:2021 - Authentication Failures",
    fix_priority="P2",
    remediation={
        "title": "Do Not Trust Cookies for Auth",
        "description": "Validate authentication server-side."
    }
),

Pattern(
    name="or_true_login",
    vuln_type="authentication_bypass",
    regex=r"(?:WHERE|AND)\s+[^;]*(?:=\s*[\'\"]?\s*\$_(?:GET|POST|REQUEST)|OR\s+1\s*=\s*1)",
    weight=85,
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Prevent SQL Login Bypass",
        "description": "Use parameterized queries to prevent OR 1=1 attacks."
    }
),

Pattern(
    name="type_juggling",
    vuln_type="authentication_bypass",
    regex=r"==\s*(?:0|false|null|\"\"|\[\])",
    weight=25,
    cwe="CWE-704",
    owasp="A07:2021 - Authentication Failures",
    fix_priority="P3",
    remediation={
        "title": "Avoid Type Juggling",
        "description": "Use strict comparisons (===)."
    }
),

Pattern(
    name="extract_globals",
    vuln_type="authentication_bypass",
    regex=r"extract\s*\(\s*\$_(?:GET|POST|REQUEST|GLOBALS)",
    weight=85,
    cwe="CWE-20",
    owasp="A01:2021 - Broken Access Control",
    fix_priority="P1",
    remediation={
        "title": "Avoid extract() on User Input",
        "description": "Access variables explicitly instead of using extract()."
    }
),

Pattern(
    name="register_globals",
    vuln_type="authentication_bypass",
    regex=r"register_globals",
    weight=50,
    cwe="CWE-20",
    owasp="A01:2021 - Broken Access Control",
    fix_priority="P2",
    remediation={
        "title": "Disable register_globals",
        "description": "Ensure register_globals is disabled in php.ini."
    }
),

Pattern(
    name="unserialize_input",
    vuln_type="authentication_bypass",
    regex=r"unserialize\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=80,
    cwe="CWE-502",
    owasp="A08:2021 - Software Integrity Failures",
    fix_priority="P1",
    remediation={
        "title": "Avoid Untrusted Deserialization",
        "description": "Never unserialize user-controlled data."
    }
),

# ============================================================
# INPUT VALIDATION
# ============================================================

Pattern(
    name="no_sanitization",
    vuln_type="input_validation",
    regex=r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*[\'\"][^\'\"]+[\'\"]\s*\](?!\s*(?:\)|,))",
    weight=20,
    cwe="CWE-20",
    owasp="A03:2021 - Injection",
    fix_priority="P3",
    remediation={
        "title": "Validate All Inputs",
        "description": "Use filter_input() or validation before processing."
    }
),

Pattern(
    name="echo_direct",
    vuln_type="input_validation",
    regex=r"echo\s+\$_(?:GET|POST|REQUEST)",
    weight=65,
    cwe="CWE-79",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Escape Output",
        "description": "Use htmlspecialchars() before echoing user input."
    }
),

Pattern(
    name="print_direct",
    vuln_type="input_validation",
    regex=r"print\s+\$_(?:GET|POST|REQUEST)",
    weight=65,
    cwe="CWE-79",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Escape Printed Output",
        "description": "Sanitize output using htmlspecialchars()."
    }
),

Pattern(
    name="direct_include",
    vuln_type="input_validation",
    regex=r"(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=80,
    cwe="CWE-98",
    owasp="A01:2021 - Broken Access Control",
    fix_priority="P1",
    remediation={
        "title": "Whitelist Include Files",
        "description": "Restrict file inclusion to allowed list."
    }
),

Pattern(
    name="eval_input",
    vuln_type="input_validation",
    regex=r"eval\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=90,
    cwe="CWE-94",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Remove eval()",
        "description": "Never execute user input as code."
    }
),

Pattern(
    name="preg_replace_e",
    vuln_type="input_validation",
    regex=r"preg_replace\s*\(\s*[\'\"][^\'\"]*/e[\'\"]",
    weight=75,
    cwe="CWE-94",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Avoid /e Modifier",
        "description": "Remove /e modifier from preg_replace."
    }
),

Pattern(
    name="system_exec",
    vuln_type="input_validation",
    regex=r"(?:system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=90,
    cwe="CWE-78",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Prevent Command Injection",
        "description": "Validate and escape shell arguments."
    }
),

Pattern(
    name="assert_input",
    vuln_type="input_validation",
    regex=r"assert\s*\(\s*\$_(?:GET|POST|REQUEST)",
    weight=85,
    cwe="CWE-94",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Avoid assert() with User Input",
        "description": "Remove assert() execution of input."
    }
),

Pattern(
    name="create_function",
    vuln_type="input_validation",
    regex=r"create_function\s*\([^,]*,\s*\$_(?:GET|POST|REQUEST)",
    weight=80,
    cwe="CWE-94",
    owasp="A03:2021 - Injection",
    fix_priority="P1",
    remediation={
        "title": "Avoid create_function()",
        "description": "Do not dynamically create functions from input."
    }
),

Pattern(
    name="file_upload",
    vuln_type="input_validation",
    regex=r"\$_FILES\s*\[\s*[\'\"][^\'\"]+[\'\"]\s*\]\s*\[\s*[\'\"](?:tmp_name|name)",
    weight=35,
    cwe="CWE-434",
    owasp="A05:2021 - Security Misconfiguration",
    fix_priority="P3",
    remediation={
        "title": "Validate File Uploads",
        "description": "Restrict file types and validate MIME type."
    }
),

Pattern(
    name="header_injection",
    vuln_type="input_validation",
    regex=r"header\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)",
    weight=60,
    cwe="CWE-113",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Prevent Header Injection",
        "description": "Validate header values before output."
    }
),

Pattern(
    name="mail_injection",
    vuln_type="input_validation",
    regex=r"mail\s*\([^)]*\$_(?:GET|POST|REQUEST)",
    weight=55,
    cwe="CWE-93",
    owasp="A03:2021 - Injection",
    fix_priority="P2",
    remediation={
        "title": "Prevent Mail Header Injection",
        "description": "Sanitize email fields before sending mail."
    }
),

# ============================================================
# SAFE PATTERNS (NEGATIVE WEIGHT)
# ============================================================

Pattern("prepared_statements","safe",
    r"(?:prepare|bindParam|bindValue|execute)\s*\(",
    -30,"N/A","Secure Coding Practice","INFO",
    {"title":"Prepared Statements Used","description":"Prepared statements mitigate SQL injection."}),

Pattern("htmlspecialchars","safe",
    r"htmlspecialchars\s*\(",
    -20,"N/A","Secure Output Encoding","INFO",
    {"title":"Output Escaping Used","description":"htmlspecialchars prevents XSS."}),

Pattern("htmlentities","safe",
    r"htmlentities\s*\(",
    -20,"N/A","Secure Output Encoding","INFO",
    {"title":"Output Encoding Used","description":"htmlentities helps prevent XSS."}),

Pattern("mysqli_real_escape","safe",
    r"mysqli_real_escape_string\s*\(",
    -15,"N/A","Secure SQL Handling","INFO",
    {"title":"Escaping Used","description":"Escaping reduces injection risk."}),

Pattern("addslashes","safe",
    r"addslashes\s*\(",
    -10,"N/A","Secure Input Handling","INFO",
    {"title":"Input Escaping Used","description":"addslashes provides minimal protection."}),

Pattern("intval","safe",
    r"intval\s*\(",
    -15,"N/A","Secure Type Casting","INFO",
    {"title":"Type Casting Used","description":"intval ensures numeric input."}),

Pattern("filter_input","safe",
    r"filter_input\s*\(",
    -25,"N/A","Secure Input Validation","INFO",
    {"title":"Input Filtering Used","description":"filter_input validates superglobals."}),

Pattern("filter_var","safe",
    r"filter_var\s*\(",
    -25,"N/A","Secure Input Validation","INFO",
    {"title":"Input Validation Used","description":"filter_var sanitizes input."}),

Pattern("preg_match_validation","safe",
    r"preg_match\s*\(\s*[\'\"][^\'\"]*(email|url|phone|digit)",
    -15,"N/A","Secure Input Validation","INFO",
    {"title":"Regex Validation Used","description":"preg_match validates format."}),

Pattern("is_numeric","safe",
    r"is_numeric\s*\(",
    -15,"N/A","Secure Validation","INFO",
    {"title":"Numeric Validation Used","description":"is_numeric validates numeric input."}),

Pattern("ctype_","safe",
    r"ctype_\w+\s*\(",
    -10,"N/A","Secure Validation","INFO",
    {"title":"Character Type Validation Used","description":"ctype functions validate characters."}),

Pattern("password_hash","safe",
    r"password_hash\s*\(",
    -25,"N/A","Secure Password Storage","INFO",
    {"title":"Secure Password Hashing Used","description":"password_hash securely stores passwords."}),

Pattern("password_verify","safe",
    r"password_verify\s*\(",
    -25,"N/A","Secure Password Verification","INFO",
    {"title":"Secure Password Verification Used","description":"password_verify prevents hash comparison flaws."}),

Pattern("csrf_token","safe",
    r"(?:csrf|token|nonce)",
    -10,"N/A","CSRF Protection","INFO",
    {"title":"CSRF Protection Detected","description":"Presence of CSRF tokens reduces CSRF risk."}),

Pattern("session_regenerate","safe",
    r"session_regenerate_id\s*\(",
    -20,"N/A","Secure Session Handling","INFO",
    {"title":"Session Regeneration Used","description":"Regenerating session ID prevents fixation attacks."}),
]