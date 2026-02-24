import re
from .pattern_registry import PATTERNS


class RuleEngine:

    def classify(self, code: str):

        results = {}

        for pattern in PATTERNS:

            if pattern.vuln_type not in results:
                results[pattern.vuln_type] = {
                    "score": 0,
                    "confidence": 0,
                    "severity": "NONE",
                    "indicators": [],
                }

            matches = re.findall(pattern.regex, code, re.IGNORECASE)

            if matches:
                results[pattern.vuln_type]["score"] = max(
                    results[pattern.vuln_type]["score"],
                    pattern.weight,
                )

                results[pattern.vuln_type]["indicators"].append(
                    {
                        "pattern": pattern.name,
                        "cwe": pattern.cwe,
                        "owasp": pattern.owasp,
                        "fix_priority": pattern.fix_priority,
                        "remediation": pattern.remediation,
                    }
                )

        for vuln, data in results.items():
            score = data["score"]
            data["confidence"] = min(score, 100)

            if score >= 70:
                data["severity"] = "CRITICAL"
            elif score >= 40:
                data["severity"] = "HIGH"
            elif score > 0:
                data["severity"] = "MEDIUM"

        return results