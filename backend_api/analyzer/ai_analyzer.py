import google.generativeai as genai
import json
import os

# --- Configuration ---
def load_config():
    """Loads the configuration from config.json."""
    # Construct the path to config.json relative to this file's directory
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config.get("GEMINI_API_KEY")
    except (FileNotFoundError, json.JSONDecodeError):
        # If config.json is missing or corrupted, key is not set
        return None

GEMINI_API_KEY = load_config()

# A placeholder check to see if the user has replaced the default key
IS_API_KEY_SET = GEMINI_API_KEY and "YOUR_API_KEY_HERE" not in GEMINI_API_KEY

def get_ai_analysis(hex_preview):
    """
    Analyzes the provided hex data using the Gemini API.

    :param hex_preview: A dictionary containing 'head' and 'tail' hex/ascii previews.
    :return: A string containing the AI's analysis, or an error/info message.
    """
    if not IS_API_KEY_SET:
        return "AI analysis skipped: Gemini API key is not configured in 'backend_api/config.json'."

    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
    except Exception as e:
        return f"AI analysis failed: Could not configure the Gemini model. Error: {e}"

    # Prepare the content for the prompt
    file_head_hex = hex_preview.get('head', '')
    file_head_ascii = hex_preview.get('head_ascii', '')
    file_tail_hex = hex_preview.get('tail', '')
    file_tail_ascii = hex_preview.get('tail_ascii', '')

    content_to_analyze = (
        f"File Head (Hex):\n{file_head_hex}\n\n"
        f"File Head (ASCII):\n{file_head_ascii}\n\n"
    )
    if file_tail_hex:
        content_to_analyze += (
            f"File Tail (Hex):\n{file_tail_hex}\n\n"
            f"File Tail (ASCII):\n{file_tail_ascii}\n"
        )

    prompt = f"""
You are a world-class cybersecurity expert and CTF (Capture The Flag) grandmaster, specializing in file format analysis, steganography, and reverse engineering.

Analyze the following hex and ASCII dump from the beginning (and possibly end) of a file. Your goal is to identify potential clues for a CTF challenge.

Focus on these areas:
1.  **File Identification**: Is the file what it appears to be? Do you see any unusual magic bytes or headers?
2.  **Hidden Data**: Are there any suspicious strings, comments, or data structures that might hide a flag or a clue? (e.g., "flag{{...", "ctf{{...", passwords, keys).
3.  **Anomalies**: Do you notice any strange patterns, non-standard data, or anything that seems out of place for a typical file of this type?
4.  **Next Steps**: Based on your analysis, what would be your top 2-3 recommended next steps or tools to use for a deeper investigation? (e.g., "Use binwalk to check for embedded files," "This looks like a custom XOR encryption, try to find the key," "The PNG IHDR chunk seems corrupted, inspect it with a hex editor.")

Provide your analysis in a concise, clear, and well-structured format.

---
**Hex/ASCII Dump to Analyze:**

{content_to_analyze}
---

**Your Expert Analysis:**
"""

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        # This will catch API errors, like authentication issues, quota limits, etc.
        return f"AI analysis failed: An error occurred while communicating with the Gemini API. Please check your API key and network connection. Error: {e}"
