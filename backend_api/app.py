import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

# Import the main analysis function
from analyzer.main_analyzer import analyze_file

# --- App Initialization ---
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing for the frontend

# --- Configuration ---
# Set a maximum file size, e.g., 50MB
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'exe', 'dll', 'bin', ''}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS or \
           '.' not in filename # Allow files with no extension

# --- API Routes ---

@app.route('/', methods=['GET'])
def index():
    """A simple route to confirm the API is running."""
    return jsonify({"status": "ok", "message": "CTF File Analyzer API is running."})

@app.route('/ctf_analyze', methods=['POST'])
def ctf_analyze_route():
    """
    The main endpoint for file analysis.
    Accepts a multipart/form-data request with a 'file' field.
    """
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
            # Catch-all for any unexpected errors during analysis
            return jsonify({
                "error": "An unexpected error occurred during analysis.",
                "details": str(e)
            }), 500

    return jsonify({"error": "Invalid file"}), 400

# --- Main Execution ---

if __name__ == '__main__':
    # Use 0.0.0.0 to make it accessible on the network
    # The default port is 5000
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=True)
