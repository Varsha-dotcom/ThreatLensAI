import os
import pickle
import pandas as pd
from app.pcap_parser import parse_pcap

def main():
    print("Testing ML PCAP Pipeline...")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pcap_path = os.path.join(base_dir, "scratch", "traffic_test.pcap")
    preprocessor_path = os.path.join(base_dir, "data", "processed", "preprocessor.pkl")
    model_path = os.path.join(base_dir, "models", "rf_model.pkl")
    
    # 1. Parse PCAP
    print(f"Parsing PCAP: {pcap_path}")
    records = parse_pcap(pcap_path)
    print(f"Parsed {len(records)} flows.")
    
    if not records:
        print("Error: No flows parsed!")
        return
        
    # 2. Extract features into DataFrame
    features_list = [
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
        "dst_host_srv_rerror_rate"
    ]
    
    features_only = [r['features'] for r in records]
    input_df = pd.DataFrame(features_only)
    input_df = input_df[features_list]
    
    print("DataFrame shape:", input_df.shape)
    print("DataFrame columns:\n", input_df.head(2))
    
    # 3. Load preprocessor and transform
    print("Loading preprocessor...")
    with open(preprocessor_path, 'rb') as f:
        preprocessor = pickle.load(f)
        
    print("Transforming features...")
    X_proc = preprocessor.transform(input_df)
    print("Preprocessed shape:", X_proc.shape)
    
    # 4. Load model and predict
    print("Loading Random Forest model...")
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
        
    print("Running model predictions...")
    preds = model.predict(X_proc)
    probs = model.predict_proba(X_proc)
    
    CODE_TO_CATEGORY = {
        0: 'Normal',
        1: 'DoS',
        2: 'Probe',
        3: 'R2L',
        4: 'U2R'
    }
    
    print("\nResults:")
    for idx, (p, prob) in enumerate(zip(preds, probs)):
        flow = records[idx]['metadata']
        proto = records[idx]['features']['protocol_type']
        srv = records[idx]['features']['service']
        flag = records[idx]['features']['flag']
        pred_label = CODE_TO_CATEGORY[int(p)]
        conf = prob[int(p)]
        print(f"Flow {idx+1}: {flow['source_ip']}:{flow['src_port']} -> {flow['dest_ip']}:{flow['dest_port']} | {proto} | {srv} | {flag} | Bytes: {records[idx]['features']['src_bytes']}/{records[idx]['features']['dst_bytes']} | Pred: {pred_label} (Conf: {conf*100:.1f}%)")
        
    print("\nAll pipeline verification tests passed successfully!")

if __name__ == '__main__':
    main()
