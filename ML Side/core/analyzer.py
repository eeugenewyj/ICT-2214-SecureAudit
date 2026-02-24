import pickle
import os
from .feature_extractor import PHPFeatureExtractor
from .rule_engine import RuleEngine


class VulnerabilityAnalyzer:
    """
    PHP Vulnerability Analyzer
    Combines rule-based and ML-based detection
    """

    def __init__(self, model_path=None):
        """
        Initialize the analyzer
        
        Args:
            model_path: Path to the pickled model file (optional)
        """
        self.rule_engine = RuleEngine()
        self.extractor = PHPFeatureExtractor()

        self.model = None
        self.scaler = None

        # Try to load ML model if path provided
        if model_path and os.path.exists(model_path):
            try:
                with open(model_path, "rb") as f:
                    data = pickle.load(f)
                    self.model = data["model"]
                    self.scaler = data["scaler"]
                    
                    # Validate feature dimensions match
                    expected_features = self.scaler.n_features_in_
                    actual_features = len(self.extractor.get_feature_names())
                    
                    if expected_features != actual_features:
                        print(f"⚠️  Warning: Feature dimension mismatch!")
                        print(f"   Model expects: {expected_features} features")
                        print(f"   Extractor provides: {actual_features} features")
                        print(f"   ML predictions disabled. Rule engine will still work.")
                        self.model = None
                        self.scaler = None
                    else:
                        print(f"✅ Model loaded successfully ({expected_features} features)")
                        
            except Exception as e:
                print(f"⚠️  Error loading model: {e}")
                print(f"   ML predictions disabled. Rule engine will still work.")
                self.model = None
                self.scaler = None
        else:
            if model_path:
                print(f"⚠️  Model file not found: {model_path}")
            print("ℹ️  Running with rule-based detection only")

    def analyze(self, code: str):
        """
        Analyze PHP code for vulnerabilities
        
        Args:
            code: PHP source code string to analyze
            
        Returns:
            dict: Analysis results containing vulnerability information
        """
        # Start with rule-based classification (always works)
        results = self.rule_engine.classify(code)

        # Add ML predictions if model is available
        if self.model and self.scaler:
            try:
                # Extract features from code
                features = self.extractor.extract_features(code)
                
                # Scale features
                features_scaled = self.scaler.transform([features])[0]
                
                # Get predictions
                probabilities = self.model.predict_proba([features_scaled])[0]
                
                # Add ML prediction info to results
                results["ml_prediction"] = {
                    "safe_probability": float(probabilities[0]) if len(probabilities) > 0 else 0.0,
                    "vulnerable_probability": float(probabilities[1]) if len(probabilities) > 1 else 0.0,
                    "prediction": "vulnerable" if probabilities[1] > 0.5 else "safe"
                }
                
            except Exception as e:
                # Don't fail the whole analysis if ML prediction fails
                print(f"⚠️  ML prediction error: {e}")
                # Continue without ML predictions

        return results

    def get_model_info(self):
        """
        Get information about the loaded model
        
        Returns:
            dict: Model information
        """
        return {
            "model_loaded": self.model is not None,
            "scaler_loaded": self.scaler is not None,
            "expected_features": self.scaler.n_features_in_ if self.scaler else None,
            "actual_features": len(self.extractor.get_feature_names()),
            "feature_names": self.extractor.get_feature_names()
        }