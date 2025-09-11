import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import the two main entry points from the analyzer
from analyzer.main_analyzer import analyze_file, analyze_for_mcp

# --- App Initialization ---
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing for the frontend

# --- Configuration ---
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# --- API Routes ---

@app.route('/', methods=['GET'])
def index():
    """A simple route to confirm the API is running."""
    return jsonify({"status": "ok", "message": "CTF File Analyzer API is running."})

@app.route('/ctf_analyze', methods=['POST'])
def ctf_analyze_route():
    """The main endpoint for the web UI."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

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

@app.route('/mcp/analyze', methods=['POST'])
def mcp_analyze_route():
    """An API endpoint designed to be called by a Large Language Model (LLM)."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    if 'command' not in request.form:
        return jsonify({"error": "No command specified in the request"}), 400

    file = request.files['file']
    command = request.form.get('command')

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        try:
            result = analyze_for_mcp(file, command)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": "An unexpected error occurred during analysis.", "details": str(e)}), 500

    return jsonify({"error": "Invalid file"}), 400

# --- Main Execution ---

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=True)
