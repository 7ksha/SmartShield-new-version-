
"""IDEA (Intrusion Detection Extensible Alert) format utilities."""
import json
from datetime import datetime, timezone
from typing import Dict, Any


def idea_format(
    category: str,
    source_ip: str,
    target_ip: str,
    description: str,
    confidence: float = 0.5,
    severity: str = "medium",
) -> Dict[str, Any]:
    """Create an IDEA-formatted alert dictionary."""
    return {
        "Format": "IDEA0",
        "ID": "",
        "DetectTime": datetime.now(timezone.utc).isoformat(),
        "EventTime": datetime.now(timezone.utc).isoformat(),
        "Category": [category],
        "Confidence": confidence,
        "Severity": severity,
        "Source": [{"IP4": [source_ip]}],
        "Target": [{"IP4": [target_ip]}],
        "Description": description,
    }


def to_json(idea_alert: Dict[str, Any]) -> str:
    """Serialize an IDEA alert to JSON."""
    return json.dumps(idea_alert, default=str)
