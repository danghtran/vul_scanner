import os
import requests
import json
import re

BASE_URL = "https://api.mistral.ai/v1"

_ENV_FILE_NAMES = ("api_key.env", "api_ley.env")


def _load_dotenv_file():
    """Load KEY=value from project-local env files if MISTRAL_API_KEY is not set."""
    if os.getenv("MISTRAL_API_KEY"):
        return
    base = os.path.dirname(os.path.abspath(__file__))
    for name in _ENV_FILE_NAMES:
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key == "MISTRAL_API_KEY" and val:
                        os.environ["MISTRAL_API_KEY"] = val
                        return
        except OSError:
            continue


_load_dotenv_file()
API_KEY = os.getenv("MISTRAL_API_KEY")

def cve_ai(keywords, model="mistral-small-latest"):
    """
    Given a list of keywords, ask Mistral to return relevant CVEs with CVSS.
    """
    if not API_KEY:
        raise ValueError("Please set MISTRAL_API_KEY in your environment.")

    prompt = f"""
    You are a cybersecurity assistant. 
    Find **relevant CVEs** for the following keywords: {", ".join(keywords)}.
    For each CVE, return:
    - CVE ID
    - Short summary
    - CVSS score (if available)

    Return only valid JSON array, nothing else.
    Example:
    [
      {{
        "cve": "CVE-2020-1234",
        "summary": "Short text...",
        "cvss": 7.5
      }}
    ]
    """

    url = f"{BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}]
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    data = response.json()

    content = data["choices"][0]["message"]["content"]
    cleaned = re.sub(r"^```(?:json)?|```$", "", content.strip(), flags=re.MULTILINE).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        return [{"raw_response": content}]