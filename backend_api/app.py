import os
import json
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from flask_cors import CORS

from analyzer.main_analyzer import analyze_file

def load_config():
    """Loads config from config.json, with fallbacks for OpenAI key and base URL."""
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.json'))

    # Default config structure
    default_config = {
        "server": {"host": "0.0.0.0", "port": 5000, "debug": False, "max_content_length": 52428800},
        "cors": {"allow_origins": "*", "allow_methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type"]},
        "security": {"allowed_extensions": ["zip", "rar", "png", "jpg", "jpeg", "gif", "bmp"], "max_file_size_mb": 50},
        "features": {"enable_string_extraction": True, "enable_entropy_analysis": True, "enable_file_structure_analysis": True, "enable_hex_preview": True},
        "openai": {"api_key": None, "api_base": "https://api.openai.com/v1"}
    }

    config = default_config
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            # Load user config and merge it into the default config
            user_config = json.load(f)
            for key, value in user_config.items():
                if isinstance(value, dict) and key in config:
                    config[key].update(value)
                else:
                    config[key] = value
            print("Configuration loaded from config.json")
    except FileNotFoundError:
        print("WARNING: config.json not found. Using default settings and environment variables.")

    # Fallback for OpenAI API Key from environment variable
    if not config.get("openai", {}).get("api_key"):
        openai_key = os.environ.get('OPENAI_API_KEY')
        if openai_key:
            if "openai" not in config:
                config["openai"] = {}
            config["openai"]["api_key"] = openai_key
            print("Loaded OPENAI_API_KEY from environment variable.")

    # Allow environment variables to override the config file
    openai_key_env = os.environ.get('OPENAI_API_KEY')
    if openai_key_env:
        config["openai"]["api_key"] = openai_key_env
        print("Loaded OPENAI_API_KEY from environment variable (override).")

    openai_base_env = os.environ.get('OPENAI_API_BASE')
    if openai_base_env:
        config["openai"]["api_base"] = openai_base_env
        print("Loaded OPENAI_API_BASE from environment variable (override).")

    return config

# Load configuration
CONFIG = load_config()

# --- App Initialization ---
app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": CONFIG['cors']})

# --- App Configuration ---
app.config['MAX_CONTENT_LENGTH'] = CONFIG['server']['max_content_length']
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend_static'))

# --- API Routes ---
@app.route('/api/health', methods=['GET'])
def health_check():
    """Confirms that the API is running."""
    return jsonify({"status": "ok"})

@app.route('/api/analyze', methods=['POST'])
def analyze_route():
    """Handles the file upload and analysis."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if file:
        try:
            analysis_results = analyze_file(file, CONFIG)
            return jsonify(analysis_results)
        except Exception as e:
            return jsonify({"error": "An unexpected error occurred during analysis.", "details": str(e)}), 500

    return jsonify({"error": "Invalid file"}), 400

# --- Static Files Routes ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_static(path):
    """Serves static files from the frontend directory."""
    if path != "" and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    else:
        return send_from_directory(FRONTEND_DIR, 'index.html')

if __name__ == '__main__':
    # This is for local development testing only.
    # Use run.py for production.
    app.run(
        host=CONFIG['server']['host'],
        port=CONFIG['server']['port'],
        debug=CONFIG['server']['debug']
    )
