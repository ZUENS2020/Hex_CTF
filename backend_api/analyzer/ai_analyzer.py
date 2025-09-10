import os
import requests
import json

def analyze_text_with_ai(text_to_analyze):
    """
    Sends text to a configurable AI API for analysis and returns the result.

    Reads configuration from environment variables:
    - AI_API_URL: The API endpoint for the AI service.
    - AI_API_KEY: The authentication token for the API.
    - AI_MODEL: The specific model to use for the analysis.

    Returns:
        A dictionary containing the AI's analysis or an error message.
    """
    api_url = os.getenv("AI_API_URL")
    api_key = os.getenv("AI_API_KEY")
    model = os.getenv("AI_MODEL")

    if not all([api_url, api_key, model]):
        return {
            "error": "AI analysis is not configured. Please set AI_API_URL, AI_API_KEY, and AI_MODEL environment variables."
        }

    system_prompt = (
        "You are a world-class CTF (Capture The Flag) challenge expert. "
        "Your task is to analyze the provided text, which was extracted from a file, "
        "and identify any potential clues, hidden messages, encoded data, passwords, "
        "or patterns relevant to solving a CTF challenge. Be concise and direct. "
        "Provide your findings as a list of actionable insights."
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze the following text for CTF clues:\n\n---\n\n{text_to_analyze}"}
        ]
    }

    # Handling Ollama's non-standard use of "Authorization: Bearer"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()

        response_data = response.json()

        # Handle different response structures (OpenAI vs. Ollama)
        if 'choices' in response_data and response_data['choices']:
            content = response_data['choices'][0]['message']['content']
        elif 'message' in response_data and 'content' in response_data['message']:
            content = response_data['message']['content']
        else:
            content = json.dumps(response_data) # Fallback to show raw response

        return {
            "model": model,
            "prompt_sent": payload["messages"][1]["content"],
            "response_received": content.strip()
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Failed to connect to AI API: {str(e)}",
            "model": model
        }
    except Exception as e:
        return {
            "error": f"An unexpected error occurred during AI analysis: {str(e)}",
            "model": model
        }
