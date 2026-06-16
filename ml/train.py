import os
import pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

def main():
    print("Starting Machine Learning Model Training (Phase 3)...")
    
    # Paths setup
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    processed_dir = os.path.join(base_dir, "data", "processed")
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)
    
    # 1. Load Processed Data
    print("Loading processed datasets...")
    X_train = pd.read_csv(os.path.join(processed_dir, "x_train.csv"))
    y_train = pd.read_csv(os.path.join(processed_dir, "y_train.csv")).values.ravel()
    
    X_val = pd.read_csv(os.path.join(processed_dir, "x_val.csv"))
    y_val = pd.read_csv(os.path.join(processed_dir, "y_val.csv")).values.ravel()
    
    X_test = pd.read_csv(os.path.join(processed_dir, "x_test.csv"))
    y_test = pd.read_csv(os.path.join(processed_dir, "y_test.csv")).values.ravel()
    
    print(f"Data Loaded:")
    print(f"  - Train features: {X_train.shape}, labels: {y_train.shape}")
    print(f"  - Val features:   {X_val.shape}, labels: {y_val.shape}")
    print(f"  - Test features:  {X_test.shape}, labels: {y_test.shape}")
    
    # 2. Train Random Forest Classifier
    # We use class_weight='balanced' to handle severe class imbalance on R2L and U2R threats.
    # n_jobs=-1 runs training in parallel on all available CPU cores.
    print("Initializing RandomForestClassifier...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )
    
    print("Training Random Forest Classifier on training split...")
    rf_model.fit(X_train, y_train)
    print("Training completed successfully!")
    
    # 3. Evaluate on Validation Split
    print("\n================ EVALUATION ON VALIDATION SPLIT ================")
    y_val_pred = rf_model.predict(X_val)
    val_accuracy = accuracy_score(y_val, y_val_pred)
    print(f"Validation Accuracy: {val_accuracy:.6f}")
    
    class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    print("\nValidation Classification Report:")
    print(classification_report(y_val, y_val_pred, target_names=class_names, digits=5))
    
    # 4. Evaluate on Test Set (containing novel, zero-day threat types)
    print("================ EVALUATION ON TESTING SET ================")
    y_test_pred = rf_model.predict(X_test)
    test_accuracy = accuracy_score(y_test, y_test_pred)
    print(f"Test Accuracy: {test_accuracy:.6f}")
    
    print("\nTest Classification Report:")
    print(classification_report(y_test, y_test_pred, target_names=class_names, digits=5))
    
    # 5. Save the trained model
    model_path = os.path.join(models_dir, "rf_model.pkl")
    print(f"\nSaving trained Random Forest model to {model_path}...")
    with open(model_path, 'wb') as f:
        pickle.dump(rf_model, f)
        
    print("Model saved and training phase completed successfully!")
    
    # 6. Generate evaluation metrics JSON
    print("Running model evaluation metrics generator...")
    try:
        import subprocess
        evaluate_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evaluate.py")
        subprocess.run(["python", evaluate_script], check=True)
        print("Model evaluation metrics generated successfully.")
    except Exception as e:
        print(f"Failed to generate evaluation metrics: {e}")

if __name__ == '__main__':
    main()
