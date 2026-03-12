import json
from openai import OpenAI
from ...licensing import get_openai_key

class AISecretValidator:
    """
    Uses AI to semantically validate suspected secrets found by entropy/regex.
    Reduces false positives by analyzing the surrounding context of a string.
    """
    def __init__(self, api_key: str = None):
        self.api_key = api_key or get_openai_key()
        self.client = OpenAI(api_key=self.api_key) if self.api_key else None

    def validate(self, secret_candidate: str, context_line: str, label: str) -> bool:
        """
        Returns True if the AI believes this is a real secret, False otherwise.
        """
        if not self.client:
            return True # Conservative default: if AI is down, assume it's a secret

        prompt = (
            f"You are a security expert analyzing a potential secret leak.\n"
            f"A scanner flagged the following string as a '{label}':\n"
            f"Candidate: {secret_candidate}\n"
            f"Found in line: {context_line}\n\n"
            f"TASK:\n"
            f"Determine if this is a REAL sensitive credential (API key, password, private key) "
            f"or a FALSE POSITIVE (e.g., a random base64 hash, a session ID, a CSRF token, or a test string).\n\n"
            f"Reasoning:\n"
            f"1. Check the variable name in 'Found in line'. Names like 'key', 'secret', 'password' are high risk.\n"
            f"2. Check the format of the candidate. Does it look like an AWS key, a JWT, or just a random hash?\n"
            f"3. Be skeptical. Developers often have long random strings that aren't secrets.\n\n"
            f"Response format: STRICT JSON ONLY\n"
            f"{{\"is_secret\": true/false, \"confidence\": 0-100, \"reason\": \"short explanation\"}}"
        )

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            result = json.loads(response.choices[0].message.content.strip())
            return result.get("is_secret", True)
        except:
            return True # Conservative fallback
