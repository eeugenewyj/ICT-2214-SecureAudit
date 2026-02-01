#!/usr/bin/env python3
"""
Model Training Script for PHP Vulnerability Classifier

Trains a machine learning model to classify PHP code vulnerabilities
and predict impact severity:
- SQL Injection
- SSRF
- Authentication Bypass
- Input Validation Issues

Impact levels: critical (3), high (2), medium (1), low/safe (0)
"""

import json
import pickle
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.multioutput import MultiOutputClassifier
import warnings
warnings.filterwarnings('ignore')

# Import the feature extractor from the main app
import sys
sys.path.insert(0, os.path.dirname(__file__))
from app import PHPFeatureExtractor

# Impact encoding
IMPACT_ENCODING = {
    'critical': 3,
    'high': 2,
    'medium': 1,
    'low': 0,
    'safe': 0
}


def load_dataset(filepath):
    """Load the dataset from JSON file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def prepare_data(dataset, extractor):
    """Prepare features and labels from the dataset.

    Labels include 4 vulnerability type columns + 1 impact severity column.
    """
    X = []
    y = []

    print("Extracting features from code samples...")
    for i, sample in enumerate(dataset):
        code = sample['code']
        features = extractor.extract_features(code)
        X.append(features)

        # Multi-label format: 4 vuln types + 1 impact severity
        impact = sample.get('impact', 'safe')
        labels = [
            sample['labels']['sql_injection'],
            sample['labels']['ssrf'],
            sample['labels']['authentication_bypass'],
            sample['labels']['input_validation'],
            IMPACT_ENCODING.get(impact, 0)
        ]
        y.append(labels)

        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(dataset)} samples")

    return np.array(X), np.array(y)


def train_model(X_train, y_train, X_test, y_test):
    """Train and evaluate the model."""
    print("\nTraining model...")

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Use RandomForest with MultiOutput wrapper for multi-label classification
    base_classifier = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_split=3,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    model = MultiOutputClassifier(base_classifier)
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)

    print("\n" + "="*60)
    print("MODEL EVALUATION RESULTS")
    print("="*60)

    vuln_labels = ['SQL Injection', 'SSRF', 'Auth Bypass', 'Input Validation']

    for i, label in enumerate(vuln_labels):
        print(f"\n{label}:")
        print("-" * 40)
        print(classification_report(y_test[:, i], y_pred[:, i], target_names=['Safe', 'Vulnerable']))

    # Impact severity evaluation
    print(f"\nImpact Severity:")
    print("-" * 40)
    impact_names = ['Safe/Low', 'Medium', 'High', 'Critical']
    # Only include labels that actually appear in the data
    unique_labels = sorted(set(y_test[:, 4]) | set(y_pred[:, 4]))
    target_names = [impact_names[int(l)] for l in unique_labels]
    print(classification_report(y_test[:, 4], y_pred[:, 4], labels=unique_labels, target_names=target_names))

    # Overall accuracy
    print("\n" + "="*60)
    print("OVERALL METRICS")
    print("="*60)

    exact_match = np.all(y_pred == y_test, axis=1).mean()
    print(f"Exact Match Ratio: {exact_match:.4f}")

    for i, label in enumerate(vuln_labels):
        acc = accuracy_score(y_test[:, i], y_pred[:, i])
        print(f"{label} Accuracy: {acc:.4f}")

    impact_acc = accuracy_score(y_test[:, 4], y_pred[:, 4])
    print(f"Impact Severity Accuracy: {impact_acc:.4f}")

    return model, scaler


def save_model(model, scaler, filepath):
    """Save the trained model and scaler."""
    data = {
        'model': model,
        'scaler': scaler,
        'version': '2.0',
        'labels': ['sql_injection', 'ssrf', 'authentication_bypass', 'input_validation', 'impact'],
        'impact_encoding': IMPACT_ENCODING
    }

    with open(filepath, 'wb') as f:
        pickle.dump(data, f)

    print(f"\nModel saved to {filepath}")


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║       PHP Vulnerability Classifier - Model Training       ║
    ║           v2.0 - With Impact Severity Prediction          ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Paths
    base_dir = os.path.dirname(__file__)
    dataset_path = os.path.join(base_dir, 'data', 'vulnerability_dataset.json')
    model_path = os.path.join(base_dir, 'model', 'vulnerability_model.pkl')

    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        print("Running dataset generator first...")
        from generate_dataset import generate_dataset
        generate_dataset(1000, dataset_path)

    # Load dataset
    print(f"Loading dataset from {dataset_path}")
    dataset = load_dataset(dataset_path)
    print(f"Loaded {len(dataset)} samples")

    # Check for impact field
    has_impact = all('impact' in s for s in dataset)
    if not has_impact:
        print("\nWARNING: Dataset missing 'impact' field. Regenerating...")
        from generate_dataset import generate_dataset
        generate_dataset(1000, dataset_path)
        dataset = load_dataset(dataset_path)

    # Initialize feature extractor
    extractor = PHPFeatureExtractor()
    print(f"Feature extractor initialized with {len(extractor.get_feature_names())} features")

    # Prepare data
    X, y = prepare_data(dataset, extractor)
    print(f"\nFeature matrix shape: {X.shape}")
    print(f"Label matrix shape: {y.shape}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y[:, 0]  # Stratify on first label
    )
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")

    # Train model
    model, scaler = train_model(X_train, y_train, X_test, y_test)

    # Save model
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    save_model(model, scaler, model_path)

    print("\n" + "="*60)
    print("Training complete!")
    print("="*60)


if __name__ == '__main__':
    main()
