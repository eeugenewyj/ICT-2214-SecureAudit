from dataclasses import dataclass
from typing import Dict


@dataclass
class Pattern:
    name: str
    vuln_type: str
    regex: str
    weight: int
    cwe: str
    owasp: str
    fix_priority: str
    remediation: Dict[str, str]