import requests
import json

def get_ai_analysis(hex_preview, config):
    """
    Analyzes the provided hex data using the OpenAI API with requests.

    :param hex_preview: A dictionary containing 'head' and 'tail' hex/ascii previews.
    :param config: The application configuration dictionary.
    :return: A string containing the AI's analysis, or an error/info message.
    """
    openai_api_key = config.get("openai", {}).get("api_key")
    is_api_key_set = openai_api_key and "YOUR_API_KEY_HERE" not in openai_api_key

    if not is_api_key_set:
        return "AI analysis skipped: OpenAI API key is not configured in 'config.json' or environment variables."

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

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {openai_api_key}"
    }

    data = {
        "model": "gpt-4",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    try:
        response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, data=json.dumps(data), timeout=15)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        return f"AI analysis failed: An error occurred while communicating with the OpenAI API. Error: {e}"
    except (KeyError, IndexError) as e:
        return f"AI analysis failed: Could not parse the response from the OpenAI API. Error: {e}"
    except Exception as e:
        return f"AI analysis failed: An unexpected error occurred. Error: {e}"
