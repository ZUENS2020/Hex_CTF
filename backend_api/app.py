import os
import json
from flask import Flask, request, jsonify, send_from_directory, redirect
from werkzeug.utils import secure_filename

# Import the main analysis function
from analyzer.main_analyzer import analyze_file

def load_config():
    """加载配置文件"""
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config.json'))
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print("警告: 配置文件不存在，使用默认配置")
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "max_content_length": 52428800
            },
            "cors": {
                "allow_origins": "*",
                "allow_methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type"]
            },
            "security": {
                "allowed_extensions": ["zip", "rar", "png", "jpg", "jpeg", "gif", "bmp"],
                "max_file_size_mb": 50
            }
        }

# 加载配置
CONFIG = load_config()

# --- App Initialization ---
app = Flask(__name__, static_folder=None)  # 禁用默认的静态文件处理
from flask_cors import CORS

# 配置 CORS
CORS(app, resources={
    r"/*": {
        "origins": CONFIG["cors"]["allow_origins"],
        "methods": CONFIG["cors"]["allow_methods"],
        "allow_headers": CONFIG["cors"]["allow_headers"]
    }
})

# --- Configuration ---
# 获取前端静态文件的绝对路径
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend_static'))
app.config['MAX_CONTENT_LENGTH'] = CONFIG["server"]["max_content_length"]

# --- Static Files Routes ---
@app.route('/')
def serve_index():
    """提供前端的主页"""
    print(f"请求根路径：METHOD={request.method}, HOST={request.host}")
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """提供所有其他静态文件"""
    print(f"请求静态文件：{filename}, METHOD={request.method}, HOST={request.host}")
    
    # 如果请求包含完整域名，重定向到正确的路径
    if 'backend_api.zuens2020.work' in filename:
        print(f"检测到域名路径，原始路径：{filename}")
        corrected_path = filename.split('backend_api.zuens2020.work/', 1)[-1]
        print(f"修正后的路径：{corrected_path}")
        return redirect(f"/{corrected_path}")
        
    return send_from_directory(FRONTEND_DIR, filename)

# --- Configuration ---
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# --- API Routes ---

# API health check route
@app.route('/api/health', methods=['GET'])
def health_check():
    """A simple route to confirm the API is running."""
    return jsonify({"status": "ok", "message": "CTF File Analyzer API is running."})

@app.route('/ctf_analyze', methods=['POST', 'OPTIONS'])
@app.route('/backend_api.zuens2020.work/ctf_analyze', methods=['POST', 'OPTIONS'])
def ctf_analyze_route():
    """The main endpoint for the web UI. Handles both local and remote requests."""
    
    if request.method == 'OPTIONS':
        # 预检请求的处理
        response = jsonify({"status": "ok"})
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    # 直接处理请求，无论路径是什么
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        try:
            analysis_results = analyze_file(file)
            return jsonify(analysis_results)
        except Exception as e:
            return jsonify({"error": "An unexpected error occurred during analysis.", "details": str(e)}), 500
    return jsonify({"error": "Invalid file"}), 400

# --- Main Execution ---

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=True)
