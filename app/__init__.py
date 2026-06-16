import os
import pickle
from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ai_soc_threat_detection_secret_key'
    
    # Locate assets relative to project directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    preprocessor_path = os.path.join(base_dir, "data", "processed", "preprocessor.pkl")
    model_path = os.path.join(base_dir, "models", "rf_model.pkl")
    
    # Initialize SQLite database
    try:
        from .db import init_db
        init_db()
    except Exception as e:
        print(f"Failed to initialize SQLite alerts database: {e}")
    
    # Load assets
    print("Loading machine learning assets on startup...")
    try:
        with open(preprocessor_path, 'rb') as f:
            app.preprocessor = pickle.load(f)
        print("Preprocessor pipeline loaded successfully.")
    except Exception as e:
        print(f"Failed to load preprocessor: {e}")
        app.preprocessor = None
        
    try:
        with open(model_path, 'rb') as f:
            app.rf_model = pickle.load(f)
        print("Random Forest model loaded successfully.")
    except Exception as e:
        print(f"Failed to load Random Forest model: {e}")
        app.rf_model = None
        
    with app.app_context():
        from . import routes
        from . import api
        
        app.register_blueprint(routes.bp)
        app.register_blueprint(api.bp)
        
    return app
