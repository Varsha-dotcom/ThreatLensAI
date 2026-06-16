import pickle
import pandas as pd
import numpy as np

# Load preprocessor and model
with open('app/assets/preprocessor.pkl', 'rb') as f:
    preprocessor = pickle.load(f)
with open('models/rf_model.pkl', 'rb') as f:
    model = pickle.load(f)

# The 41 original network traffic features used to train the preprocessor/model
FEATURES_LIST = [
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

CODE_TO_CATEGORY = {0: 'Normal', 1: 'DoS', 2: 'Probe', 3: 'R2L', 4: 'U2R'}

def test_prediction(features_dict, name):
    # Construct complete dictionary with defaults
    record = {f: 0 for f in FEATURES_LIST}
    # Float defaults
    for f in ["serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", 
              "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", 
              "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
              "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
              "dst_host_serror_rate", "dst_host_srv_serror_rate", 
              "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]:
        record[f] = 0.0
    record["same_srv_rate"] = 1.0
    record["dst_host_same_srv_rate"] = 1.0
    record["protocol_type"] = "tcp"
    record["service"] = "http"
    record["flag"] = "SF"
    
    # Apply overrides
    record.update(features_dict)
    
    # Predict
    df = pd.DataFrame([record])[FEATURES_LIST]
    X_proc = preprocessor.transform(df)
    pred_code = model.predict(X_proc)[0]
    pred_label = CODE_TO_CATEGORY[int(pred_code)]
    probs = model.predict_proba(X_proc)[0]
    prob_dist = {CODE_TO_CATEGORY[i]: float(probs[i]) for i in range(5)}
    
    print(f"\n[{name}] Predicted: {pred_label} (Confidence: {probs[pred_code]*100:.1f}%)")
    print("Probabilities:", {k: f"{v*100:.1f}%" for k, v in prob_dist.items() if v > 0.01})
    
    # Return features used
    clean_record = {k: v for k, v in record.items() if v != 0 and v != 0.0 and v != 'SF' and v != 'http' and v != 'tcp'}
    # Also include keys that we explicitly want
    for k in ["protocol_type", "service", "flag"]:
        clean_record[k] = record[k]
    print("Non-default parameters:", clean_record)

print("--- TESTING PRESETS ---")

# 1. Normal
test_prediction({
    "service": "ftp_data",
    "src_bytes": 491,
    "count": 2,
    "srv_count": 2,
    "dst_host_count": 150,
    "dst_host_srv_count": 25,
    "dst_host_same_srv_rate": 0.17,
    "dst_host_diff_srv_rate": 0.03,
    "dst_host_same_src_port_rate": 0.17,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.05,
    "dst_host_srv_rerror_rate": 0.0
}, "Normal HTTP")

# 2. DoS (Neptune)
test_prediction({
    "service": "private",
    "flag": "S0",
    "count": 123,
    "srv_count": 6,
    "serror_rate": 1.0,
    "srv_serror_rate": 1.0,
    "same_srv_rate": 0.05,
    "diff_srv_rate": 0.07,
    "dst_host_count": 255,
    "dst_host_srv_count": 26,
    "dst_host_same_srv_rate": 0.1,
    "dst_host_diff_srv_rate": 0.05,
    "dst_host_serror_rate": 1.0,
    "dst_host_srv_serror_rate": 1.0,
    "wrong_fragment": 3
}, "Neptune DoS")

# 3. Probe (Satan / Portscan)
test_prediction({
    "service": "private",
    "flag": "REJ",
    "count": 500,
    "srv_count": 500,
    "dst_host_count": 255,
    "dst_host_srv_count": 1,
    "dst_host_same_srv_rate": 0.0,
    "dst_host_diff_srv_rate": 1.0,
    "rerror_rate": 1.0,
    "srv_rerror_rate": 1.0,
    "dst_host_rerror_rate": 1.0,
    "dst_host_srv_rerror_rate": 1.0,
    "hot": 3
}, "Satan Probe")

# 4. R2L (Brute Force / Guess Password)
# Let's try to find an override that triggers R2L
test_prediction({
    "service": "telnet",
    "flag": "SF",
    "num_failed_logins": 85,
    "hot": 4,
    "logged_in": 0,
    "is_guest_login": 1,
    "count": 1,
    "srv_count": 1,
    "dst_host_count": 2,
    "dst_host_srv_count": 2,
}, "R2L Brute Force Telnet")

# Let's try U2R
test_prediction({
    "service": "telnet",
    "flag": "SF",
    "root_shell": 1,
    "su_attempted": 1,
    "num_root": 2,
    "logged_in": 1,
    "duration": 60,
    "num_file_creations": 1,
    "num_shells": 1
}, "U2R Root Access")
