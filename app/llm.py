
import os
import requests
from dotenv import load_dotenv
 
load_dotenv()  # reads variables from a .env file in the project root, if present
 
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "openai/gpt-oss-20b"  # OpenAI's open-source (open-weight) model, hosted by Groq
 
 
def generate_response(prompt: str) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return (
            "[No GROQ_API_KEY set. This is a placeholder response. "
            "Set the GROQ_API_KEY environment variable (or .env file) and restart "
            "the server to get real AI answers.]"
        )
 
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 300,
    }
 
    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        return f"[Error contacting the LLM: {e}]"
 