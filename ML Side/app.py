#!/usr/bin/env python3
"""
MLModel - PHP Vulnerability Classifier
Component #2: Flask web application for ML-based PHP code vulnerability detection

This application classifies PHP code for the following vulnerabilities:
- SQL Injection
- SSRF (Server-Side Request Forgery)
- Authentication Bypass
- Input Validation Issues
"""

from flask import Flask, render_template, request, jsonify
import pickle
import os
import re
import numpy as np
from datetime import datetime

app = Flask(__name__)

# Vulnerability categories
VULNERABILITY_TYPES = [
    'sql_injection',
    'ssrf',
    'authentication_bypass',
    'input_validation'
]

# Feature extraction patterns for PHP code analysis
class PHPFeatureExtractor:
    """Extract features from PHP code for vulnerability classification."""

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

    # SSRF indicators
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

    # Safe patterns (reduce vulnerability score)
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

    def __init__(self):
        self.feature_names = []
        self._build_feature_names()

    def _build_feature_names(self):
        """Build list of feature names."""
        for pattern_name in self.SQL_PATTERNS:
            self.feature_names.append(f'sql_{pattern_name}')
        for pattern_name in self.SSRF_PATTERNS:
            self.feature_names.append(f'ssrf_{pattern_name}')
        for pattern_name in self.AUTH_BYPASS_PATTERNS:
            self.feature_names.append(f'auth_{pattern_name}')
        for pattern_name in self.INPUT_VALIDATION_PATTERNS:
            self.feature_names.append(f'input_{pattern_name}')
        for pattern_name in self.SAFE_PATTERNS:
            self.feature_names.append(f'safe_{pattern_name}')
        # Additional statistical features
        self.feature_names.extend([
            'code_length',
            'line_count',
            'function_count',
            'variable_count',
            'user_input_count',
            'db_operation_count'
        ])

    def extract_features(self, code):
        """Extract features from PHP code."""
        features = []

        # SQL Injection features
        for pattern_name, pattern in self.SQL_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # SSRF features
        for pattern_name, pattern in self.SSRF_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Authentication Bypass features
        for pattern_name, pattern in self.AUTH_BYPASS_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Input Validation features
        for pattern_name, pattern in self.INPUT_VALIDATION_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Safe pattern features
        for pattern_name, pattern in self.SAFE_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Statistical features
        features.append(len(code))  # code_length
        features.append(code.count('\n') + 1)  # line_count
        features.append(len(re.findall(r'function\s+\w+\s*\(', code)))  # function_count
        features.append(len(re.findall(r'\$\w+', code)))  # variable_count
        features.append(len(re.findall(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)', code)))  # user_input_count
        features.append(len(re.findall(r'(?:mysql|mysqli|PDO|pg_|sqlite)', code, re.IGNORECASE)))  # db_operation_count

        return np.array(features)

    def get_feature_names(self):
        """Return list of feature names."""
        return self.feature_names


class RuleBasedClassifier:
    """Rule-based classifier for PHP vulnerabilities when ML model is not available."""

    def __init__(self):
        self.extractor = PHPFeatureExtractor()

    def classify(self, code):
        """Classify code using pattern matching rules."""
        results = {
            'sql_injection': {'score': 0, 'confidence': 0, 'indicators': []},
            'ssrf': {'score': 0, 'confidence': 0, 'indicators': []},
            'authentication_bypass': {'score': 0, 'confidence': 0, 'indicators': []},
            'input_validation': {'score': 0, 'confidence': 0, 'indicators': []}
        }

        # Check SQL Injection patterns
        for pattern_name, pattern in self.extractor.SQL_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                results['sql_injection']['score'] += len(matches) * 10
                results['sql_injection']['indicators'].append({
                    'pattern': pattern_name,
                    'count': len(matches),
                    'sample': matches[0][:100] if matches else ''
                })

        # Check SSRF patterns
        for pattern_name, pattern in self.extractor.SSRF_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                results['ssrf']['score'] += len(matches) * 10
                results['ssrf']['indicators'].append({
                    'pattern': pattern_name,
                    'count': len(matches),
                    'sample': matches[0][:100] if matches else ''
                })

        # Check Authentication Bypass patterns
        for pattern_name, pattern in self.extractor.AUTH_BYPASS_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                results['authentication_bypass']['score'] += len(matches) * 10
                results['authentication_bypass']['indicators'].append({
                    'pattern': pattern_name,
                    'count': len(matches),
                    'sample': matches[0][:100] if matches else ''
                })

        # Check Input Validation patterns
        for pattern_name, pattern in self.extractor.INPUT_VALIDATION_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                results['input_validation']['score'] += len(matches) * 10
                results['input_validation']['indicators'].append({
                    'pattern': pattern_name,
                    'count': len(matches),
                    'sample': matches[0][:100] if matches else ''
                })

        # Apply safe pattern deductions
        for pattern_name, pattern in self.extractor.SAFE_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                # Reduce scores for each vulnerability type
                for vuln_type in results:
                    results[vuln_type]['score'] = max(0, results[vuln_type]['score'] - len(matches) * 5)

        # Calculate confidence levels (0-100)
        for vuln_type in results:
            score = results[vuln_type]['score']
            results[vuln_type]['confidence'] = min(100, score)

        return results


class VulnerabilityAnalyzer:
    """Main analyzer that uses ML model or falls back to rule-based classification."""

    def __init__(self, model_path=None):
        self.extractor = PHPFeatureExtractor()
        self.rule_classifier = RuleBasedClassifier()
        self.model = None
        self.scaler = None

        if model_path and os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data.get('model')
                    self.scaler = data.get('scaler')
                print(f"[+] ML model loaded from {model_path}")
            except Exception as e:
                print(f"[-] Failed to load model: {e}")
                self.model = None

    def analyze(self, code):
        """Analyze PHP code for vulnerabilities."""
        # Get rule-based results first
        rule_results = self.rule_classifier.classify(code)

        # If ML model is available, enhance with ML predictions
        if self.model is not None:
            try:
                features = self.extractor.extract_features(code)
                if self.scaler:
                    features = self.scaler.transform([features])[0]
                ml_prediction = self.model.predict_proba([features])[0]

                # Combine ML predictions with rule-based results
                for i, vuln_type in enumerate(VULNERABILITY_TYPES):
                    if i < len(ml_prediction):
                        # Weighted average of rule-based and ML scores
                        rule_conf = rule_results[vuln_type]['confidence']
                        ml_conf = ml_prediction[i] * 100
                        rule_results[vuln_type]['confidence'] = int(0.4 * rule_conf + 0.6 * ml_conf)
                        rule_results[vuln_type]['ml_score'] = ml_conf
            except Exception as e:
                print(f"[-] ML prediction error: {e}")

        # Generate recommendations
        recommendations = self._generate_recommendations(rule_results)
        rule_results['recommendations'] = recommendations

        # Determine overall risk level
        max_confidence = max(r['confidence'] for r in rule_results.values() if isinstance(r, dict) and 'confidence' in r)
        if max_confidence >= 70:
            rule_results['risk_level'] = 'HIGH'
        elif max_confidence >= 40:
            rule_results['risk_level'] = 'MEDIUM'
        elif max_confidence > 0:
            rule_results['risk_level'] = 'LOW'
        else:
            rule_results['risk_level'] = 'SAFE'

        return rule_results

    def _generate_recommendations(self, results):
        """Generate remediation recommendations based on findings."""
        recommendations = []

        if results['sql_injection']['confidence'] > 30:
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

        if results['ssrf']['confidence'] > 30:
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

        if results['authentication_bypass']['confidence'] > 30:
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

        if results['input_validation']['confidence'] > 30:
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


# Initialize the analyzer
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model', 'vulnerability_model.pkl')
analyzer = VulnerabilityAnalyzer(MODEL_PATH)


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_code():
    """Analyze submitted PHP code."""
    try:
        data = request.get_json()
        code = data.get('code', '')

        if not code or not code.strip():
            return jsonify({
                'error': 'No code provided',
                'success': False
            }), 400

        # Perform analysis
        results = analyzer.analyze(code)
        results['success'] = True
        results['timestamp'] = datetime.now().isoformat()

        return jsonify(results)

    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': analyzer.model is not None,
        'timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         MLModel - PHP Vulnerability Classifier            ║
    ║     SQL Injection | SSRF | Auth Bypass | Input Validation ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=5000, debug=True)
