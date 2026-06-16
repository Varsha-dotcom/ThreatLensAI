from flask import Blueprint, jsonify, current_app, render_template

bp = Blueprint('routes', __name__)

@bp.route('/')
def index():
    return render_template('dashboard.html')

@bp.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "preprocessor_loaded": current_app.preprocessor is not None,
        "model_loaded": current_app.rf_model is not None,
        "threat_classes": {
            "0": "Normal",
            "1": "DoS",
            "2": "Probe",
            "3": "R2L",
            "4": "U2R"
        }
    }), 200
