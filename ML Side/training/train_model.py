"""
Train ML model for PHP vulnerability detection
Uses the 64-pattern feature extractor
"""
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
        
        # Extract features
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
    
    # Initialize model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=20,
        min_samples_leaf=10,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    # Train model
    model.fit(X_train, y_train)
    
    print("  Model training complete")
    
    return model


def evaluate_model(model, X_test, y_test, scaler=None):
    """Evaluate model performance"""
    print("\nEvaluating model...")
    
    # Make predictions
    if scaler:
        X_test_scaled = scaler.transform(X_test)
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)
    else:
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"MODEL PERFORMANCE")
    print(f"{'='*60}")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                Safe  Vulnerable")
    print(f"Actual Safe      {cm[0][0]:4d}  {cm[0][1]:4d}")
    print(f"       Vulnerable {cm[1][0]:4d}  {cm[1][1]:4d}")
    
    # Classification report
    print(f"\nDetailed Classification Report:")
    print(classification_report(
        y_test, 
        y_pred, 
        target_names=['Safe', 'Vulnerable']
    ))
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': cm.tolist()
    }


def save_model(model, scaler, metrics, output_path, feature_names):
    """Save trained model and metadata"""
    print(f"\nSaving model to {output_path}...")
    
    # Create model directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Package model with metadata
    model_package = {
        'model': model,
        'scaler': scaler,
        'metrics': metrics,
        'feature_names': feature_names,
        'n_features': len(feature_names)
    }
    
    # Save to pickle file
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
    
    # Get feature importances
    importances = model.feature_importances_
    
    # Sort by importance
    indices = np.argsort(importances)[::-1]
    
    print(f"\n{'Rank':<6} {'Feature':<40} {'Importance':<12}")
    print(f"{'-'*60}")
    
    for i, idx in enumerate(indices[:top_n], 1):
        feature_name = feature_names[idx]
        importance = importances[idx]
        print(f"{i:<6} {feature_name:<40} {importance:.6f}")


def main():
    """Main training pipeline"""
    
    print("="*60)
    print("PHP VULNERABILITY DETECTION - MODEL TRAINING")
    print("="*60)
    
    # Paths
    dataset_path = os.path.join(
        os.path.dirname(__file__), 
        '..', 
        'data', 
        'vulnerability_dataset.json'
    )
    
    model_path = os.path.join(
        os.path.dirname(__file__), 
        '..', 
        'model', 
        'vulnerability_model.pkl'
    )
    
    # Step 1: Load dataset
    dataset = load_dataset(dataset_path)
    
    # Step 2: Initialize feature extractor
    print("\nInitializing feature extractor...")
    extractor = PHPFeatureExtractor()
    feature_names = extractor.get_feature_names()
    print(f"    Feature extractor ready")
    print(f"   Total features: {len(feature_names)}")
    
    # Step 3: Extract features from training data
    X_train, y_train = extract_features_from_samples(
        dataset['train'], 
        extractor
    )
    
    # Step 4: Extract features from test data
    X_test, y_test = extract_features_from_samples(
        dataset['test'], 
        extractor
    )
    
    # Step 5: Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("    Feature scaling complete")
    
    # Step 6: Train model
    model = train_model(X_train_scaled, y_train)
    
    # Step 7: Evaluate model
    metrics = evaluate_model(model, X_test, y_test, scaler)
    
    # Step 8: Display feature importance
    display_feature_importance(model, feature_names)
    
    # Step 9: Save model
    save_model(model, scaler, metrics, model_path, feature_names)
    
    print(f"\n{'='*60}")
    print(f"TRAINING COMPLETE!")
    print(f"{'='*60}")
    print(f"\nModel is ready to use!")
    print(f"Location: {model_path}")
    print(f"\nTo use the model:")
    print(f"1. Restart your Flask server: python run.py")
    print(f"2. The model will be automatically loaded")
    print(f"3. Test with: curl -X POST http://localhost:5001/analyze \\")
    print(f"     -H 'Content-Type: application/json' \\")
    print(f"     -d '{{\"code\": \"<?php echo \\$_GET[\\\"x\\\"]; ?>\"}}'")
    print(f"\n{'='*60}")


if __name__ == "__main__":
    main()