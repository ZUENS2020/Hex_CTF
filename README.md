# Full-Stack CTF File Analyzer

This project is a complete web-based file analysis tool designed for Capture The Flag (CTF) competitions. It consists of a Python Flask backend for deep file analysis and a lightweight vanilla JavaScript frontend for user interaction. The tool helps players quickly identify file anomalies, hidden information, pseudo-encryption, steganography, and other common CTF clues.

It is designed for easy deployment on both **Windows** and **CentOS/Linux** environments and features an extensible integration with AI APIs (like OpenAI, Gemini, or local models via Ollama) for enhanced analysis.

## Project Structure

```
.
├── backend_api/
│   ├── analyzer/
│   │   ├── ai_analyzer.py
│   │   └── main_analyzer.py
│   ├── app.py
│   ├── requirements.txt
│   └── .env.example
├── frontend_static/
│   ├── index.html
│   ├── script.js
│   └── style.css
└── README.md
```

## Core Features

- **File Upload & Hex/ASCII Preview**: Upload any file and view its head and tail in a hex editor format.
- **File Type Analysis**: Detects file types using Magic Bytes and `libmagic`, highlighting mismatches with file extensions.
- **String Extraction**: Pulls all printable strings and uses regex to highlight potential `flag{...}` formats.
- **Entropy Analysis**: Calculates Shannon entropy to identify packed or encrypted data sections.
- **ZIP Analysis**: Detects pseudo-encryption, CRC errors, and global comments in ZIP archives.
- **EOF Data Detection**: Finds data appended past the standard end-of-file markers for formats like JPG and PNG.
- **AI-Powered Analysis**: Integrates with major AI APIs to analyze extracted text for deeper insights and potential clues.

---

## Part 1: Backend Setup (Flask API)

The backend is a Python Flask application that performs all the analysis.

### Step 1: Prerequisites

- **Python 3.8+**
- **pip** (Python package installer)

#### Installation:
- **Windows**: Download from [python.org](https://www.python.org/) and install. **Make sure to check "Add Python to PATH"** during installation.
- **CentOS/RHEL**: `sudo yum install python3 python3-pip` or `sudo dnf install python3 python3-pip`.

### Step 2: Create a Virtual Environment

It is highly recommended to use a virtual environment to manage dependencies.

Navigate to the project's root directory.

```bash
# Move into the backend directory
cd backend_api

# Create the virtual environment
python3 -m venv venv
```

### Step 3: Activate the Environment & Install Dependencies

- **Windows (Command Prompt):**
  ```cmd
  .\venv\Scripts\activate
  ```
- **Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **CentOS/Linux (Bash):**
  ```bash
  source venv/bin/activate
  ```

Once activated, install the required packages:
```bash
pip install -r requirements.txt
```

### Step 4: Configure AI Analysis (Optional but Recommended)

To use the AI-powered analysis, you need to provide API credentials.

1.  **Copy the example file:** In the `backend_api` directory, copy `.env.example` to a new file named `.env`.
    - **Windows:** `copy .env.example .env`
    - **CentOS/Linux:** `cp .env.example .env`

2.  **Edit the `.env` file** with your details:
    ```ini
    # For OpenAI
    AI_API_URL="https://api.openai.com/v1/chat/completions"
    AI_API_KEY="your_openai_api_key_here"
    AI_MODEL="gpt-4"

    # For a local Ollama instance
    # AI_API_URL="http://localhost:11434/api/chat"
    # AI_API_KEY="ollama" # Can be any non-empty string
    # AI_MODEL="llama3"
    ```

### Step 5: Run the Backend Server

Make sure you are in the `backend_api` directory with the virtual environment activated.

```bash
# The server will run on http://localhost:5000 by default
flask run --host=0.0.0.0
```
The backend API is now running and ready to accept requests.

---

## Part 2: Frontend Setup (Static Web App)

The frontend is a set of static HTML, CSS, and JS files. It can be served by any simple web server.

### Easy Method: Python's Built-in Server

This method works on both Windows and CentOS/Linux, provided you have Python installed.

1.  Open a **new terminal** (do not close your backend terminal).
2.  Navigate to the `frontend_static` directory.
    ```bash
    cd frontend_static
    ```
3.  Start the HTTP server.
    ```bash
    # For Python 3
    python3 -m http.server 8080
    ```
    The server will typically run on port 8080.

### Accessing the Application

Once both the backend and frontend servers are running:

1.  Open your web browser.
2.  Navigate to the frontend URL: **`http://localhost:8080`** (or whichever port you used).

You can now upload files and see the analysis results. The frontend will communicate with the backend API running on port 5000. If your backend is on a different URL, you can edit the `API_BASE_URL` constant at the top of `frontend_static/script.js`.
