# core/__init__.py
from .analyzer import VulnerabilityAnalyzer
from .feature_extractor import PHPFeatureExtractor
from .pattern_registry import PATTERNS
from .pattern_class import Pattern
from .rule_engine import RuleEngine

__all__ = [
    'VulnerabilityAnalyzer',
    'PHPFeatureExtractor',
    'PATTERNS',
    'Pattern',
    'RuleEngine'
]