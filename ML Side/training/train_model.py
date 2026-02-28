import json
import pickle
import os
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import cross_val_score, StratifiedKFold

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feature_extractor import PHPFeatureExtractor


def load_dataset(dataset_path):
    """Load the generated dataset"""
    print(f"Loading dataset from {dataset_path}...")

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"Dataset not found at {dataset_path}\n"
            "Please run 'python generate_data.py' first"
        )

    with open(dataset_path, 'r') as f:
        dataset = json.load(f)

    print(f"Loaded dataset:")
    print(f"   Train samples: {len(dataset['train'])}")
    print(f"   Test samples: {len(dataset['test'])}")

    return dataset


def extract_features_from_samples(samples, extractor):
    """Extract features from code samples"""
    print(f"\nExtracting features from {len(samples)} samples...")

    X = []
    y = []

    for i, sample in enumerate(samples):
        code = sample['code']
        label = sample['label']

        features = extractor.extract_features(code)
        X.append(features)
        y.append(label)

        if (i + 1) % 100 == 0:
            print(f"  Processed {i + 1}/{len(samples)} samples")

    X = np.array(X)
    y = np.array(y)

    print(f"   Feature extraction complete")
    print(f"   Feature shape: {X.shape}")
    print(f"   Labels shape: {y.shape}")

    return X, y


def train_model(X_train, y_train):
    """Train Random Forest classifier"""
    print("\nTraining Random Forest model...")
    print(f"  Training samples: {len(X_train)}")
    print(f"  Features per sample: {X_train.shape[1]}")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,          # Reduced from 20 to prevent overfitting
        min_samples_split=20, # Increased from 5
        min_samples_leaf=10,  # Increased from 2
        max_features='sqrt',
        random_state=42,
        n_jobs=-1,
        verbose=1
    )

    model.fit(X_train, y_train)
    print("  Model training complete")

    return model


def cross_validate_model(model, X_train, y_train, n_splits=5):
    """
    Run stratified k-fold cross-validation on the training set.

    A large gap between CV score and held-out test score is the main
    signal of overfitting.  Ideally CV mean and test F1 should be within
    ~2-3 percentage points of each other.
    """
    print(f"\n{'='*60}")
    print(f"CROSS-VALIDATION  ({n_splits}-fold Stratified)")
    print(f"{'='*60}")

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)

    metrics = {
        'accuracy':  cross_val_score(model, X_train, y_train, cv=cv, scoring='accuracy'),
        'precision': cross_val_score(model, X_train, y_train, cv=cv, scoring='precision'),
        'recall':    cross_val_score(model, X_train, y_train, cv=cv, scoring='recall'),
        'f1':        cross_val_score(model, X_train, y_train, cv=cv, scoring='f1'),
    }

    print(f"\n{'Metric':<12} {'Mean':>8}  {'Std':>8}  {'Min':>8}  {'Max':>8}")
    print(f"{'-'*50}")
    for name, scores in metrics.items():
        print(
            f"{name:<12} "
            f"{scores.mean():>8.4f}  "
            f"{scores.std():>8.4f}  "
            f"{scores.min():>8.4f}  "
            f"{scores.max():>8.4f}"
        )

    print(f"\n  Fold-by-fold F1 scores: {[f'{s:.4f}' for s in metrics['f1']]}")

    # Overfitting warning — if CV F1 drops more than 5 points vs max
    cv_f1_mean = metrics['f1'].mean()
    if cv_f1_mean < 0.80:
        print(f"\n  [WARNING] CV F1 mean ({cv_f1_mean:.4f}) is low — model may be underfitting.")
    elif metrics['f1'].std() > 0.05:
        print(f"\n  [WARNING] High variance across folds (std={metrics['f1'].std():.4f}) — "
              f"consider more data or stronger regularisation.")
    else:
        print(f"\n  [OK] CV scores look stable.")

    return {name: {'mean': float(s.mean()), 'std': float(s.std())} for name, s in metrics.items()}


def evaluate_model(model, X_test, y_test, cv_metrics=None, scaler=None):
    """
    Evaluate model on the held-out test set and compare against CV scores
    to surface any overfitting gap.
    """
    print(f"\n{'='*60}")
    print(f"HELD-OUT TEST SET PERFORMANCE")
    print(f"{'='*60}")

    if scaler:
        X_test_scaled = scaler.transform(X_test)
        y_pred = model.predict(X_test_scaled)
    else:
        y_pred = model.predict(X_test)

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)

    print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")

    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                Safe  Vulnerable")
    print(f"Actual Safe      {cm[0][0]:4d}  {cm[0][1]:4d}")
    print(f"       Vulnerable {cm[1][0]:4d}  {cm[1][1]:4d}")

    print(f"\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Vulnerable']))

    # ── Overfitting gap report ───────────────────────────────────────────
    if cv_metrics:
        print(f"{'='*60}")
        print(f"OVERFITTING GAP  (CV mean  vs  Test score)")
        print(f"{'='*60}")
        print(f"\n{'Metric':<12} {'CV Mean':>10}  {'Test':>10}  {'Gap':>10}  {'Status':>10}")
        print(f"{'-'*56}")

        test_scores = {
            'accuracy':  accuracy,
            'precision': precision,
            'recall':    recall,
            'f1':        f1,
        }

        for name in ('accuracy', 'precision', 'recall', 'f1'):
            cv_mean = cv_metrics[name]['mean']
            test_val = test_scores[name]
            gap = test_val - cv_mean          # positive = test > CV (mild overfit)
            abs_gap = abs(gap)

            if abs_gap < 0.03:
                status = "OK"
            elif abs_gap < 0.07:
                status = "WARN"
            else:
                status = "OVERFIT" if gap > 0 else "UNDERFIT"

            print(
                f"{name:<12} "
                f"{cv_mean:>10.4f}  "
                f"{test_val:>10.4f}  "
                f"{gap:>+10.4f}  "
                f"{status:>10}"
            )

        overall_gap = f1 - cv_metrics['f1']['mean']
        if abs(overall_gap) > 0.07:
            print(
                f"\n  [ACTION REQUIRED] F1 gap of {overall_gap:+.4f} exceeds threshold.\n"
                f"  → If test > CV: increase min_samples_leaf, reduce max_depth, or add more diverse data.\n"
                f"  → If CV > test: your test split may be too small or skewed."
            )
        else:
            print(f"\n  [OK] F1 gap of {overall_gap:+.4f} is within acceptable range.")

    return {
        'accuracy':         accuracy,
        'precision':        precision,
        'recall':           recall,
        'f1':               f1,
        'confusion_matrix': cm.tolist(),
        'cv_metrics':       cv_metrics,
    }


def save_model(model, scaler, metrics, output_path, feature_names):
    """Save trained model and metadata"""
    print(f"\nSaving model to {output_path}...")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    model_package = {
        'model':         model,
        'scaler':        scaler,
        'metrics':       metrics,
        'feature_names': feature_names,
        'n_features':    len(feature_names)
    }

    with open(output_path, 'wb') as f:
        pickle.dump(model_package, f)

    file_size = os.path.getsize(output_path)
    print(f"    Model saved successfully")
    print(f"   File: {output_path}")
    print(f"   Size: {file_size / 1024:.2f} KB")
    print(f"   Features: {len(feature_names)}")


def display_feature_importance(model, feature_names, top_n=20):
    """Display most important features"""
    print(f"\n{'='*60}")
    print(f"TOP {top_n} MOST IMPORTANT FEATURES")
    print(f"{'='*60}")

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    print(f"\n{'Rank':<6} {'Feature':<40} {'Importance':<12}")
    print(f"{'-'*60}")

    for i, idx in enumerate(indices[:top_n], 1):
        print(f"{i:<6} {feature_names[idx]:<40} {importances[idx]:.6f}")


def main():
    """Main training pipeline"""

    print("="*60)
    print("PHP VULNERABILITY DETECTION - MODEL TRAINING")
    print("="*60)

    dataset_path = os.path.join(
        os.path.dirname(__file__), '..', 'data', 'vulnerability_dataset.json'
    )
    model_path = os.path.join(
        os.path.dirname(__file__), '..', 'model', 'vulnerability_model.pkl'
    )

    # Step 1: Load dataset
    dataset = load_dataset(dataset_path)

    # Step 2: Initialize feature extractor
    print("\nInitializing feature extractor...")
    extractor = PHPFeatureExtractor()
    feature_names = extractor.get_feature_names()
    print(f"    Feature extractor ready — {len(feature_names)} features")

    # Step 3 & 4: Extract features
    X_train, y_train = extract_features_from_samples(dataset['train'], extractor)
    X_test,  y_test  = extract_features_from_samples(dataset['test'],  extractor)

    # Step 5: Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)
    print("    Feature scaling complete")

    # Step 6: Train model
    model = train_model(X_train_scaled, y_train)

    # Step 7: Cross-validate on training data BEFORE looking at test set
    cv_metrics = cross_validate_model(model, X_train_scaled, y_train, n_splits=5)

    # Step 8: Evaluate on held-out test set + compare vs CV
    metrics = evaluate_model(model, X_test, y_test, cv_metrics=cv_metrics, scaler=scaler)

    # Step 9: Feature importance
    display_feature_importance(model, feature_names)

    # Step 10: Save
    save_model(model, scaler, metrics, model_path, feature_names)

    print(f"\n{'='*60}")
    print(f"TRAINING COMPLETE!")
    print(f"{'='*60}")
    print(f"\nModel saved to: {model_path}")
    print(f"\nTo use the model:")
    print(f"1. Restart your Flask server: python run.py")
    print(f"2. The model will be automatically loaded")
    print(f"3. Test with: curl -X POST http://localhost:5001/analyze \\")
    print(f"     -H 'Content-Type: application/json' \\")
    print(f"     -d '{{\"code\": \"<?php echo \\$_GET[\\\"x\\\"]; ?>\"}}'")
    print(f"\n{'='*60}")


if __name__ == "__main__":
    main()