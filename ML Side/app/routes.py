from flask import Blueprint, request, jsonify, current_app, render_template
from datetime import datetime

# Create Blueprint
api = Blueprint("api", __name__)

@api.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@api.route("/analyze", methods=["POST"])
def analyze_code():
    try:
        data = request.get_json()

        if not data or "code" not in data:
            return jsonify({
                "success": False,
                "error": "No code provided"
            }), 400

        code = data["code"]

        if not code.strip():
            return jsonify({
                "success": False,
                "error": "Empty code submission"
            }), 400

        # Call analyzer stored in app config
        analyzer = current_app.config["ANALYZER"]
        raw_results = analyzer.analyze(code)
        
        # Format results for frontend
        formatted_results = format_results_for_frontend(raw_results)

        return jsonify({
            "success": True,
            "timestamp": datetime.utcnow().isoformat(),
            "results": raw_results,  # Keep original detailed results
            **formatted_results  # Add formatted fields at top level
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


def format_results_for_frontend(results):
    """
    Format analyzer results for frontend display
    
    The frontend expects:
    - riskLevel: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "SAFE"
    - vulnerabilities: array of vulnerability objects
    - overallScore: numeric score
    """
    
    vulnerabilities = []
    max_severity = "NONE"
    max_score = 0
    
    # Severity ranking for comparison
    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "NONE": 0
    }
    
    # Process each vulnerability type from results
    for vuln_type, vuln_data in results.items():
        # Skip ML prediction and non-vulnerability entries
        if vuln_type == "ml_prediction":
            continue
            
        severity = vuln_data.get("severity", "NONE")
        score = vuln_data.get("score", 0)
        confidence = vuln_data.get("confidence", 0)
        indicators = vuln_data.get("indicators", [])
        
        # Only process if there are actual indicators (vulnerabilities found)
        if indicators and score > 0:
            # Track highest severity
            if severity_rank.get(severity, 0) > severity_rank.get(max_severity, 0):
                max_severity = severity
            
            # Track highest score
            if score > max_score:
                max_score = score
            
            # Add each indicator as a vulnerability
            for indicator in indicators:
                vulnerabilities.append({
                    "type": vuln_type,
                    "severity": severity,
                    "score": score,
                    "confidence": confidence,
                    "pattern": indicator.get("pattern", ""),
                    "cwe": indicator.get("cwe", ""),
                    "owasp": indicator.get("owasp", ""),
                    "fix_priority": indicator.get("fix_priority", ""),
                    "remediation": indicator.get("remediation", {})
                })
    
    # Determine overall risk level
    if max_severity == "NONE" or not vulnerabilities:
        risk_level = "SAFE"
    else:
        risk_level = max_severity  # CRITICAL, HIGH, MEDIUM, or LOW
    
    return {
        "riskLevel": risk_level,
        "overallScore": max_score,
        "vulnerabilities": vulnerabilities,
        "vulnerabilityCount": len(vulnerabilities),
        "hasVulnerabilities": len(vulnerabilities) > 0
    }


@api.route("/health", methods=["GET"])
def health():
    analyzer = current_app.config["ANALYZER"]

    return jsonify({
        "status": "healthy",
        "model_loaded": analyzer.model is not None,
        "timestamp": datetime.utcnow().isoformat()
    })