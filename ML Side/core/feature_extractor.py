import re
import numpy as np
from .pattern_registry import PATTERNS


class PHPFeatureExtractor:

    def __init__(self):
        self.patterns = PATTERNS
        self.feature_names = [p.name for p in PATTERNS]
        self.feature_names += [
            "code_length",
            "line_count",
            "function_count",
            "variable_count",
            "user_input_count",
            "db_operation_count",
        ]

    def extract_features(self, code: str):

        features = []

        for pattern in self.patterns:
            count = len(re.findall(pattern.regex, code, re.IGNORECASE))
            features.append(count)

        # statistical features
        features.append(len(code))
        features.append(code.count("\n") + 1)
        features.append(len(re.findall(r"function\s+\w+\s*\(", code)))
        features.append(len(re.findall(r"\$\w+", code)))
        features.append(
            len(re.findall(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)", code))
        )
        features.append(
            len(re.findall(r"(?:mysql|mysqli|PDO|pg_|sqlite)", code, re.IGNORECASE))
        )

        return np.array(features)

    def get_feature_names(self):
        return self.feature_names