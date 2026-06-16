import os
import json
import pickle
import pandas as pd
import numpy as np
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

def main():
    print("Starting Machine Learning Model Evaluation...")
    
    # Dynamic workspace directory lookup
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    processed_dir = os.path.join(base_dir, "data", "processed")
    models_dir = os.path.join(base_dir, "models")
    static_dir = os.path.join(base_dir, "app", "static")
    
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)
    
    # 1. Load Processed Data
    print("Loading processed datasets...")
    X_train = pd.read_csv(os.path.join(processed_dir, "x_train.csv"))
    y_train = pd.read_csv(os.path.join(processed_dir, "y_train.csv")).values.ravel()
    
    X_val = pd.read_csv(os.path.join(processed_dir, "x_val.csv"))
    y_val = pd.read_csv(os.path.join(processed_dir, "y_val.csv")).values.ravel()
    
    X_test = pd.read_csv(os.path.join(processed_dir, "x_test.csv"))
    y_test = pd.read_csv(os.path.join(processed_dir, "y_test.csv")).values.ravel()
    
    print(f"Data Loaded successfully:")
    print(f"  - Train features: {X_train.shape}")
    print(f"  - Val features:   {X_val.shape}")
    print(f"  - Test features:  {X_test.shape}")
    
    # 2. Load Model
    model_path = os.path.join(models_dir, "rf_model.pkl")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Trained model not found at {model_path}. Please run train.py first.")
        
    print(f"Loading model from {model_path}...")
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
        
    # 3. Predict & Calculate Test Metrics
    print("Running inference on testing split...")
    y_pred = model.predict(X_test)
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    report = classification_report(y_test, y_pred, target_names=class_names, digits=5, output_dict=True)
    
    # 4. Class Distributions
    train_dist = {name: int(np.sum(y_train == i)) for i, name in enumerate(class_names)}
    val_dist = {name: int(np.sum(y_val == i)) for i, name in enumerate(class_names)}
    test_dist = {name: int(np.sum(y_test == i)) for i, name in enumerate(class_names)}
    
    # 5. Extract Feature Importances
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    top_features = []
    # Get top 10 features
    for idx in indices[:10]:
        top_features.append({
            "name": X_train.columns[idx],
            "importance": float(importances[idx])
        })
        
    # 6. Model Info Metadata
    model_info = {
        "model_name": type(model).__name__,
        "n_estimators": int(model.n_estimators),
        "random_state": int(model.random_state) if model.random_state is not None else None,
        "class_weight": str(model.class_weight),
        "n_features_in": int(model.n_features_in_),
        "num_classes": len(model.classes_),
        "classes": [class_names[int(c)] for c in model.classes_],
        "training_samples": len(y_train),
        "validation_samples": len(y_val),
        "test_samples": len(y_test),
        "timestamp": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # 7. Assemble Metrics Payload
    # Extract overall metrics
    precision_macro = report['macro avg']['precision']
    recall_macro = report['macro avg']['recall']
    f1_macro = report['macro avg']['f1-score']
    
    metrics_payload = {
        "accuracy": float(accuracy),
        "precision": float(precision_macro),
        "recall": float(recall_macro),
        "f1_score": float(f1_macro),
        "class_metrics": {
            name: {
                "precision": float(report[name]['precision']),
                "recall": float(report[name]['recall']),
                "f1_score": float(report[name]['f1-score']),
                "support": int(report[name]['support'])
            } for name in class_names
        },
        "confusion_matrix": cm.tolist(),
        "class_distribution": {
            "train": train_dist,
            "val": val_dist,
            "test": test_dist
        },
        "top_features": top_features,
        "model_info": model_info
    }
    
    # Save output to both models/metrics.json and app/static/metrics.json for fallback
    models_metrics_path = os.path.join(models_dir, "metrics.json")
    static_metrics_path = os.path.join(static_dir, "metrics.json")
    
    print(f"Saving metrics.json to {models_metrics_path}...")
    with open(models_metrics_path, 'w') as f:
        json.dump(metrics_payload, f, indent=4)
        
    print(f"Saving metrics.json copy to {static_metrics_path}...")
    with open(static_metrics_path, 'w') as f:
        json.dump(metrics_payload, f, indent=4)
        
    print("Model evaluation metrics successfully generated and saved!")

if __name__ == '__main__':
    main()
