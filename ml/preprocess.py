import os
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

# Column Names definition
COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
    "logged_in", "num_compromised", "root_shell", "su_attempted", 
    "num_root", "num_file_creations", "num_shells", "num_access_files", 
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count", 
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", 
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", 
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", 
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", 
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", 
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

# Mapping specific attack labels to high-level categories
ATTACK_MAPPING = {
    # DoS attacks
    'back': 'dos',
    'land': 'dos',
    'neptune': 'dos',
    'pod': 'dos',
    'smurf': 'dos',
    'teardrop': 'dos',
    'apache2': 'dos',
    'udpstorm': 'dos',
    'processtable': 'dos',
    'worm': 'dos',
    'mailbomb': 'dos',
    
    # Probe attacks
    'satan': 'probe',
    'ipsweep': 'probe',
    'nmap': 'probe',
    'portsweep': 'probe',
    'mscan': 'probe',
    'saint': 'probe',
    
    # R2L attacks
    'guess_passwd': 'r2l',
    'ftp_write': 'r2l',
    'imap': 'r2l',
    'phf': 'r2l',
    'multihop': 'r2l',
    'warezmaster': 'r2l',
    'warezclient': 'r2l',
    'spy': 'r2l',
    'xlock': 'r2l',
    'xsnoop': 'r2l',
    'snmpguess': 'r2l',
    'snmpgetattack': 'r2l',
    'httptunnel': 'r2l',
    'sendmail': 'r2l',
    'named': 'r2l',
    
    # U2R attacks
    'buffer_overflow': 'u2r',
    'loadmodule': 'u2r',
    'rootkit': 'u2r',
    'perl': 'u2r',
    'sqlattack': 'u2r',
    'xterm': 'u2r',
    'ps': 'u2r',
}

# Integer encoding of target categories
CATEGORY_TO_INT = {
    'normal': 0,
    'dos': 1,
    'probe': 2,
    'r2l': 3,
    'u2r': 4
}

def map_label(label):
    label_clean = label.strip().lower()
    if label_clean == 'normal':
        return 0
    cat = ATTACK_MAPPING.get(label_clean)
    if cat is None:
        print(f"Warning: Unknown attack label '{label}' mapped to DoS by default.")
        cat = 'dos'
    return CATEGORY_TO_INT[cat]

def main():
    print("Starting data preprocessing pipeline...")
    
    # Paths setup
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    raw_dir = os.path.join(base_dir, "data", "raw")
    processed_dir = os.path.join(base_dir, "data", "processed")
    os.makedirs(processed_dir, exist_ok=True)
    
    train_path = os.path.join(raw_dir, "KDDTrain+.txt")
    test_path = os.path.join(raw_dir, "KDDTest+.txt")
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError("Raw NSL-KDD data files not found in data/raw. Please run Phase 1 first.")
        
    # 1. Load Datasets
    print("Loading raw datasets...")
    train_df = pd.read_csv(train_path, names=COLUMN_NAMES)
    test_df = pd.read_csv(test_path, names=COLUMN_NAMES)
    
    # 2. Extract Labels and Drop Metadata
    # Drop difficulty_level to avoid data leakage / bias
    print("Extracting targets and dropping metadata columns...")
    y_train_full = train_df['label'].apply(map_label).values
    y_test = test_df['label'].apply(map_label).values
    
    X_train_full = train_df.drop(columns=['label', 'difficulty_level'])
    X_test = test_df.drop(columns=['label', 'difficulty_level'])
    
    # 3. Stratified Train-Validation Split (80% Train, 20% Validation)
    print("Creating stratified Train/Validation split...")
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full, 
        y_train_full, 
        test_size=0.20, 
        random_state=42, 
        stratify=y_train_full
    )
    
    print(f"Split sizes: Train={X_train.shape[0]}, Val={X_val.shape[0]}, Test={X_test.shape[0]}")
    
    # 4. Feature Transformations Setup
    categorical_cols = ['protocol_type', 'service', 'flag']
    numerical_cols = [col for col in X_train.columns if col not in categorical_cols]
    
    # Use ColumnTransformer for clean and isolated preprocessing
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols)
        ]
    )
    
    # 5. Fit Transformer on Train and Transform splits
    print("Fitting preprocessor pipeline on training features...")
    preprocessor.fit(X_train)
    
    # Get feature names after one-hot encoding
    encoded_cat_features = preprocessor.named_transformers_['cat'].get_feature_names_out(categorical_cols).tolist()
    feature_names = numerical_cols + encoded_cat_features
    
    print(f"Transforming features (Total output features = {len(feature_names)})...")
    X_train_proc = preprocessor.transform(X_train)
    X_val_proc = preprocessor.transform(X_val)
    X_test_proc = preprocessor.transform(X_test)
    
    # Create DataFrames to keep column names
    X_train_df = pd.DataFrame(X_train_proc, columns=feature_names)
    X_val_df = pd.DataFrame(X_val_proc, columns=feature_names)
    X_test_df = pd.DataFrame(X_test_proc, columns=feature_names)
    
    y_train_df = pd.DataFrame(y_train, columns=['label'])
    y_val_df = pd.DataFrame(y_val, columns=['label'])
    y_test_df = pd.DataFrame(y_test, columns=['label'])
    
    # 6. Verify processed features
    assert not X_train_df.isnull().any().any(), "Train features contain NaN values!"
    assert not X_val_df.isnull().any().any(), "Val features contain NaN values!"
    assert not X_test_df.isnull().any().any(), "Test features contain NaN values!"
    assert X_train_df.shape[1] == X_test_df.shape[1], "Feature dimensions do not match between Train and Test!"
    print("Integrity check passed.")
    
    # 7. Save Processed Splits
    print("Saving processed CSV datasets to data/processed/...")
    X_train_df.to_csv(os.path.join(processed_dir, "x_train.csv"), index=False)
    y_train_df.to_csv(os.path.join(processed_dir, "y_train.csv"), index=False)
    
    X_val_df.to_csv(os.path.join(processed_dir, "x_val.csv"), index=False)
    y_val_df.to_csv(os.path.join(processed_dir, "y_val.csv"), index=False)
    
    X_test_df.to_csv(os.path.join(processed_dir, "x_test.csv"), index=False)
    y_test_df.to_csv(os.path.join(processed_dir, "y_test.csv"), index=False)
    
    # 8. Save serialized preprocessor pipeline
    preprocessor_path = os.path.join(processed_dir, "preprocessor.pkl")
    print(f"Saving serialized preprocessor pipeline to {preprocessor_path}...")
    with open(preprocessor_path, 'wb') as f:
        pickle.dump(preprocessor, f)
        
    print("Preprocessing completed successfully!")
    print(f"Output shapes:")
    print(f"  - X_train: {X_train_df.shape}, y_train: {y_train_df.shape}")
    print(f"  - X_val:   {X_val_df.shape}, y_val:   {y_val_df.shape}")
    print(f"  - X_test:  {X_test_df.shape}, y_test:  {y_test_df.shape}")

if __name__ == '__main__':
    main()
