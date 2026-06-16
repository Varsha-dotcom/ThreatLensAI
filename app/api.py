from flask import Blueprint, request, jsonify, current_app
import pandas as pd
import numpy as np

bp = Blueprint('api', __name__)

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

# Numeric mapping to string threat names
CODE_TO_CATEGORY = {
    0: 'Normal',
    1: 'DoS',
    2: 'Probe',
    3: 'R2L',
    4: 'U2R'
}

def prioritize_alert(record, prediction, confidence):
    # Base score by threat category
    base_scores = {
        'Normal': 0,
        'DoS': 45,
        'Probe': 60,
        'R2L': 80,
        'U2R': 95
    }
    
    if prediction == 'Normal':
        return 0, 'Low', 'Benign network connection.', 'No mitigation required.'
        
    score = base_scores.get(prediction, 50)
    reasons = []
    
    # 1. Failed Logins Trigger
    failed_logins = int(record.get('num_failed_logins', 0))
    if failed_logins > 0:
        boost = min(failed_logins * 5, 20)
        score += boost
        reasons.append(f"{failed_logins} failed login attempt(s)")
        
    # 2. Privilege Escalation Triggers
    root_shell = int(record.get('root_shell', 0))
    su_attempted = int(record.get('su_attempted', 0))
    if root_shell == 1 or su_attempted > 0:
        score += 15
        reasons.append("unauthorized root shell access")
        
    # 3. Connection Anomalies
    hot = int(record.get('hot', 0))
    if hot > 2:
        score += 10
        reasons.append("suspicious access flags triggered")
        
    wrong_frag = int(record.get('wrong_fragment', 0))
    if wrong_frag > 0:
        score += 12
        reasons.append(f"malformed packet fragments ({wrong_frag})")
        
    # 4. Volumetric Flooding
    count = int(record.get('count', 0))
    if prediction == 'DoS' and count > 150:
        score += 10
        reasons.append(f"high frequency packet flood ({count} same host connections)")

    # Weight score with model confidence
    score = score * (0.8 + 0.2 * confidence)
    
    # Cap score at 100, min at 10 for verified threats
    score = max(min(round(score), 100), 10)
    
    # Define Priority Level
    if score >= 90:
        level = 'Critical'
    elif score >= 75:
        level = 'High'
    elif score >= 40:
        level = 'Medium'
    else:
        level = 'Low'
        
    # Format description string
    if not reasons:
        reason_str = f"Threat signature match ({prediction}) verified with {confidence*100:.1f}% confidence."
    else:
        reason_str = f"Threat vector verified with {confidence*100:.1f}% confidence: " + ", ".join(reasons) + "."
        
    # Automated Mitigation Playbooks
    actions = {
        'DoS': 'Block port and deploy rate-limiting rules on perimeter firewall.',
        'Probe': 'Blackhole source IP address and check target network port vulnerabilities.',
        'R2L': 'Force target user credential rotation and reset active session key tokens.',
        'U2R': 'Quarantine target machine (Isolate Network Node) and terminate child root processes.'
    }
    action = actions.get(prediction, 'Inspect log details and enforce firewall restrictions.')
    
    return score, level, reason_str, action

@bp.route('/api/predict', methods=['POST'])
def predict():
    # 1. Validate loaded model state
    if current_app.rf_model is None or current_app.preprocessor is None:
        return jsonify({
            "status": "error",
            "message": "Model or preprocessor pipeline assets are not loaded on server. Check logs."
        }), 503
        
    # 2. Get and validate JSON payload
    if not request.is_json:
        return jsonify({
            "status": "error",
            "message": "Invalid request: Payload must be JSON"
        }), 400
        
    data = request.get_json()
    if data is None:
        return jsonify({
            "status": "error",
            "message": "Empty JSON payload"
        }), 400
        
    # 3. Determine if payload is single or batch list
    if isinstance(data, dict):
        records = [data]
        is_batch = False
    elif isinstance(data, list):
        records = data
        is_batch = True
    else:
        return jsonify({
            "status": "error",
            "message": "Payload format must be a JSON object (single record) or a JSON array (batch records)"
        }), 400
        
    # 4. Check for missing columns in each record
    validation_errors = []
    for idx, record in enumerate(records):
        missing_features = [feature for feature in FEATURES_LIST if feature not in record]
        if missing_features:
            validation_errors.append({
                "record_index": idx,
                "missing_features": missing_features
            })
            
    if validation_errors:
        return jsonify({
            "status": "error",
            "message": "Input validation failed: missing required features",
            "errors": validation_errors
        }), 400
        
    # 5. Build DataFrame and ensure column order
    try:
        input_df = pd.DataFrame(records)
        input_df = input_df[FEATURES_LIST]  # Strict column alignment
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to structure input features: {str(e)}"
        }), 400
        
    # 6. Apply preprocessor scaling and one-hot encoding
    try:
        X_proc = current_app.preprocessor.transform(input_df)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Feature preprocessing failed: {str(e)}. Check category names."
        }), 500
        
    # 7. Run model inference
    try:
        predictions = current_app.rf_model.predict(X_proc)
        probabilities = current_app.rf_model.predict_proba(X_proc)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Model inference execution failed: {str(e)}"
        }), 500
        
    # 8. Construct response results with prioritization engine
    results = []
    for idx, (pred_code, prob_vector) in enumerate(zip(predictions, probabilities)):
        pred_label = CODE_TO_CATEGORY[int(pred_code)]
        confidence = float(prob_vector[int(pred_code)])
        prob_distribution = {CODE_TO_CATEGORY[i]: float(prob_vector[i]) for i in range(5)}
        
        # Calculate prioritization metrics
        record_raw = records[idx]
        priority_score, priority_level, priority_reason, playbook_action = prioritize_alert(
            record_raw, pred_label, confidence
        )
        
        results.append({
            "prediction": pred_label,
            "category_code": int(pred_code),
            "confidence": confidence,
            "probabilities": prob_distribution,
            "priority_score": priority_score,
            "priority_level": priority_level,
            "priority_reason": priority_reason,
            "playbook_action": playbook_action
        })
        
    if is_batch:
        return jsonify({
            "status": "success",
            "predictions": results
        }), 200
    else:
        # For single prediction, flatten the response fields for ease of access
        res = results[0]
        return jsonify({
            "status": "success",
            "prediction": res["prediction"],
            "category_code": res["category_code"],
            "confidence": res["confidence"],
            "probabilities": res["probabilities"],
            "priority_score": res["priority_score"],
            "priority_level": res["priority_level"],
            "priority_reason": res["priority_reason"],
            "playbook_action": res["playbook_action"]
        }), 200

@bp.route('/api/metrics', methods=['GET'])
def get_metrics():
    import os
    import json
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    metrics_path = os.path.join(base_dir, "models", "metrics.json")
    
    if not os.path.exists(metrics_path):
        # Fallback to static copy
        metrics_path = os.path.join(base_dir, "app", "static", "metrics.json")
        
    if not os.path.exists(metrics_path):
        return jsonify({
            "status": "error",
            "message": "Model evaluation metrics file metrics.json not found."
        }), 404
        
    try:
        with open(metrics_path, 'r') as f:
            metrics_data = json.load(f)
        return jsonify(metrics_data), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to load metrics: {str(e)}"
        }), 500

@bp.route('/api/upload_pcap', methods=['POST'])
def upload_pcap():
    import os
    from werkzeug.utils import secure_filename
    from .pcap_parser import parse_pcap
    from .db import insert_alerts
    
    if current_app.rf_model is None or current_app.preprocessor is None:
        return jsonify({
            "status": "error",
            "message": "Model or preprocessor pipeline assets are not loaded on server."
        }), 503
        
    if 'file' not in request.files:
        return jsonify({
            "status": "error",
            "message": "No file part in the request"
        }), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({
            "status": "error",
            "message": "No selected file"
        }), 400
        
    if not (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
        return jsonify({
            "status": "error",
            "message": "Invalid file extension: Only .pcap or .pcapng are supported."
        }), 400
        
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    upload_dir = os.path.join(base_dir, "scratch")
    os.makedirs(upload_dir, exist_ok=True)
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)
    
    try:
        records = parse_pcap(filepath)
        
        if not records:
            return jsonify({
                "status": "success",
                "summary": {
                    "total_packets": 0,
                    "total_flows": 0,
                    "threat_count": 0,
                    "max_risk": 0
                },
                "results": []
            }), 200
            
        features_only = [r['features'] for r in records]
        input_df = pd.DataFrame(features_only)
        input_df = input_df[FEATURES_LIST]
        
        X_proc = current_app.preprocessor.transform(input_df)
        predictions = current_app.rf_model.predict(X_proc)
        probabilities = current_app.rf_model.predict_proba(X_proc)
        
        results = []
        threats_to_save = []
        max_risk = 0
        threat_count = 0
        
        for idx, r in enumerate(records):
            pred_code = predictions[idx]
            prob_vector = probabilities[idx]
            pred_label = CODE_TO_CATEGORY[int(pred_code)]
            confidence = float(prob_vector[int(pred_code)])
            
            priority_score, priority_level, priority_reason, playbook_action = prioritize_alert(
                r['features'], pred_label, confidence
            )
            
            flow_res = {
                "timestamp": r['metadata']['timestamp'],
                "source_ip": r['metadata']['source_ip'],
                "dest_ip": r['metadata']['dest_ip'],
                "src_port": r['metadata']['src_port'],
                "dest_port": r['metadata']['dest_port'],
                "protocol": r['features']['protocol_type'],
                "packet_count": r['metadata']['pkt_count'],
                "src_bytes": r['features']['src_bytes'],
                "dst_bytes": r['features']['dst_bytes'],
                "flag": r['features']['flag'],
                "service": r['features']['service'],
                "prediction": pred_label,
                "confidence": confidence,
                "priority_score": priority_score,
                "priority_level": priority_level,
                "priority_reason": priority_reason,
                "playbook_action": playbook_action
            }
            
            results.append(flow_res)
            
            if pred_label != 'Normal':
                threat_count += 1
                threats_to_save.append(flow_res)
                if priority_score > max_risk:
                    max_risk = priority_score
                    
        if threats_to_save:
            insert_alerts(threats_to_save)
            
        total_packets = sum([r['metadata']['pkt_count'] for r in records])
        
        summary = {
            "total_packets": total_packets,
            "total_flows": len(records),
            "threat_count": threat_count,
            "max_risk": max_risk
        }
        
        return jsonify({
            "status": "success",
            "summary": summary,
            "results": results
        }), 200
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": f"PCAP analysis failed: {str(e)}"
        }), 500
    finally:
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

@bp.route('/api/db_alerts', methods=['GET'])
def get_db_alerts():
    from .db import get_alerts
    try:
        limit = request.args.get('limit', default=100, type=int)
        alerts_list = get_alerts(limit)
        return jsonify({
            "status": "success",
            "alerts": alerts_list
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Failed to retrieve alerts: {str(e)}"
        }), 500
