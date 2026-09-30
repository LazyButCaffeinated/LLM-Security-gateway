"""
logger.py

A very simple, in-memory security event log. Every block, redaction, or
allowed request gets appended here, so you can view what the gateway
has caught during your demo via GET /logs.

Kept intentionally simple (no database) since the focus of this version
is attack detection, not user/role management.
"""

import datetime

_events = []


def log_event(event_type: str, detail: str, prompt: str = ""):
    _events.append({
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "event_type": event_type,
        "detail": detail,
        "prompt_preview": prompt[:80],
    })


def get_events():
    return list(reversed(_events))  # most recent first
