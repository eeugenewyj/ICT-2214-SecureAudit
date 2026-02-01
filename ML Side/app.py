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
from PHP_Patterns import (
    SQL_PATTERNS, SSRF_PATTERNS, AUTH_BYPASS_PATTERNS,
    INPUT_VALIDATION_PATTERNS, SAFE_PATTERNS
)
from PHP_Recommendations import generate_recommendations

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

    # Pattern dictionaries imported from PHP_Patterns.py
    SQL_PATTERNS = SQL_PATTERNS
    SSRF_PATTERNS = SSRF_PATTERNS
    AUTH_BYPASS_PATTERNS = AUTH_BYPASS_PATTERNS
    INPUT_VALIDATION_PATTERNS = INPUT_VALIDATION_PATTERNS
    SAFE_PATTERNS = SAFE_PATTERNS

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
        for pattern_name, (pattern, weight) in self.SQL_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # SSRF features
        for pattern_name, (pattern, weight) in self.SSRF_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Authentication Bypass features
        for pattern_name, (pattern, weight) in self.AUTH_BYPASS_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Input Validation features
        for pattern_name, (pattern, weight) in self.INPUT_VALIDATION_PATTERNS.items():
            count = len(re.findall(pattern, code, re.IGNORECASE))
            features.append(count)

        # Safe pattern features
        for pattern_name, (pattern, weight) in self.SAFE_PATTERNS.items():
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
        """Classify code using weighted pattern matching rules.

        Each pattern has an associated severity weight that reflects its
        real-world impact. The highest weight among matched patterns
        determines the base confidence score for that vulnerability type.
        Additional matches add smaller increments.
        """
        results = {
            'sql_injection': {'score': 0, 'confidence': 0, 'indicators': [], 'severity': 'NONE'},
            'ssrf': {'score': 0, 'confidence': 0, 'indicators': [], 'severity': 'NONE'},
            'authentication_bypass': {'score': 0, 'confidence': 0, 'indicators': [], 'severity': 'NONE'},
            'input_validation': {'score': 0, 'confidence': 0, 'indicators': [], 'severity': 'NONE'}
        }

        # Map vulnerability types to their pattern dictionaries
        vuln_pattern_map = {
            'sql_injection': self.extractor.SQL_PATTERNS,
            'ssrf': self.extractor.SSRF_PATTERNS,
            'authentication_bypass': self.extractor.AUTH_BYPASS_PATTERNS,
            'input_validation': self.extractor.INPUT_VALIDATION_PATTERNS,
        }

        # Check patterns for each vulnerability type using severity weights
        for vuln_type, patterns in vuln_pattern_map.items():
            max_weight = 0
            for pattern_name, (pattern, weight) in patterns.items():
                matches = re.findall(pattern, code, re.IGNORECASE)
                if matches:
                    # Track the highest severity weight found
                    max_weight = max(max_weight, weight)
                    # Add smaller increment for additional pattern matches
                    results[vuln_type]['score'] += weight
                    results[vuln_type]['indicators'].append({
                        'pattern': pattern_name,
                        'count': len(matches),
                        'weight': weight,
                        'sample': matches[0][:100] if matches else ''
                    })
            # Use the highest matched pattern weight as the base confidence
            # This ensures a single critical pattern = high confidence
            if max_weight > 0:
                results[vuln_type]['score'] = max_weight

        # Apply safe pattern deductions
        for pattern_name, (pattern, deduction) in self.extractor.SAFE_PATTERNS.items():
            matches = re.findall(pattern, code, re.IGNORECASE)
            if matches:
                for vuln_type in results:
                    results[vuln_type]['score'] = max(0, results[vuln_type]['score'] - len(matches) * deduction)

        # Calculate confidence levels (0-100) and assign severity labels
        for vuln_type in results:
            score = results[vuln_type]['score']
            results[vuln_type]['confidence'] = min(100, score)
            # Assign severity based on confidence
            conf = results[vuln_type]['confidence']
            if conf >= 70:
                results[vuln_type]['severity'] = 'CRITICAL'
            elif conf >= 40:
                results[vuln_type]['severity'] = 'HIGH'
            elif conf > 0:
                results[vuln_type]['severity'] = 'MEDIUM'
            else:
                results[vuln_type]['severity'] = 'NONE'
            # Clear indicators if safe patterns reduced confidence to 0
            if results[vuln_type]['confidence'] == 0:
                results[vuln_type]['indicators'] = []

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

        # Generate recommendations using imported function
        recommendations = generate_recommendations(rule_results)
        rule_results['recommendations'] = recommendations

        # Determine overall risk level based on highest severity found
        max_confidence = max(r['confidence'] for r in rule_results.values() if isinstance(r, dict) and 'confidence' in r)
        if max_confidence >= 70:
            rule_results['risk_level'] = 'CRITICAL'
        elif max_confidence >= 40:
            rule_results['risk_level'] = 'HIGH'
        elif max_confidence > 0:
            rule_results['risk_level'] = 'MEDIUM'
        else:
            rule_results['risk_level'] = 'SAFE'

        return rule_results


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
