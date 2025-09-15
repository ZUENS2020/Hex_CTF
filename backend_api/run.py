import os
import sys
from app import app, CONFIG

def main():
    """Main function to run the Flask app."""
    host = CONFIG["server"]["host"]
    port = CONFIG["server"]["port"]
    debug = CONFIG["server"]["debug"]

    print(f"Starting server at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    # Ensure the working directory is correct
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    main()
