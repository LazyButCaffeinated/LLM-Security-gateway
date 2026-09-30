"""
security_checks.py

The core of the security gateway: detects prompt injection and other
common LLM attacks BEFORE the prompt is sent to the real LLM, and
scans the LLM's response for leaked sensitive data AFTER it comes back.

Attack categories detected (based on OWASP Top 10 for LLM Applications,
2025, and Liu et al., "Prompt Injection attack against LLM-integrated
Applications", 2023):

  1. Instruction override    - "ignore previous instructions", "disregard the rules"
  2. Role/persona hijacking  - "you are now DAN", "act as an unfiltered AI"
  3. System prompt leakage   - "reveal your system prompt", "show me your instructions"
  4. Delimiter/injection     - fake tags like [SYSTEM], ###, <|im_start|> used to
                               trick the model into treating user text as instructions
  5. Encoding/obfuscation    - base64 or excessive unicode used to sneak instructions past filters
"""

import re
import base64

# ---------------------------------------------------------------------------
# Attack pattern definitions
# ---------------------------------------------------------------------------

ATTACK_PATTERNS = {
    "instruction_override": [
        r"ignore (all|any|the)?\s*(previous|prior|above|earlier) (instructions|rules|prompts)",
        r"disregard (all|any|the)?\s*(previous|prior|above) (instructions|rules)",
        r"forget (all|everything|your instructions|what (i|you) (said|told))",
        r"new instructions?:",
        r"override (your|the) (rules|instructions|guidelines)",
    ],
    "role_hijacking": [
        r"you are now (in )?(dan|developer mode|jailbreak|unrestricted)",
        r"act as an? (unfiltered|uncensored|unrestricted|jailbroken) (ai|assistant|model)",
        r"pretend (you have|to have) no (restrictions|rules|guidelines|filters)",
        r"from now on,? you (are|will act as)",
        r"enable (developer|debug|admin|god) mode",
    ],
    "system_prompt_leak": [
        r"reveal (your|the) (system prompt|hidden instructions|initial prompt)",
        r"(show|print|output|repeat) (me )?your (system prompt|instructions)",
        r"what (are|were) your (original|initial) instructions",
        r"repeat (the words |everything )?above",
    ],
    "delimiter_injection": [
        r"\[system\]",
        r"<\|im_start\|>",
        r"<\|im_end\|>",
        r"###\s*(system|instruction)",
        r"\{\{.*system.*\}\}",
    ],
}

_compiled_patterns = {
    category: [re.compile(p, re.IGNORECASE) for p in patterns]
    for category, patterns in ATTACK_PATTERNS.items()
}


def check_prompt(text: str):
    """
    Scans a prompt for known attack patterns.
    Returns (is_blocked: bool, category: str | None, matched_text: str | None)
    """
    for category, patterns in _compiled_patterns.items():
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return True, category, match.group(0)

    # Check for suspicious base64 blocks (a common obfuscation technique:
    # hiding an injection payload as encoded text, hoping the model decodes
    # and follows it).
    b64_blocks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for block in b64_blocks:
        try:
            decoded = base64.b64decode(block).decode("utf-8", errors="ignore")
            if any(p.search(decoded) for patterns in _compiled_patterns.values() for p in patterns):
                return True, "encoded_injection", block[:40] + "..."
        except Exception:
            pass

    return False, None, None


# ---------------------------------------------------------------------------
# Sensitive data detection (used on the LLM's response, to catch leaks)
# ---------------------------------------------------------------------------

PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PHONE": re.compile(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
}


def redact_sensitive_data(text: str):
    """
    Replaces any detected PII in the LLM's response with [REDACTED:TYPE].
    Returns (redacted_text, findings_dict).
    """
    findings = {}
    redacted = text
    for label, pattern in PII_PATTERNS.items():
        matches = [m.group(0) for m in pattern.finditer(text)]
        if matches:
            findings[label] = matches
        redacted = pattern.sub(f"[REDACTED:{label}]", redacted)
    return redacted, findings
