

"""
Alert dataclass and utilities for SmartShield.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
from uuid import uuid4

from smartshield_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    ThreatLevel,
)


@dataclass
class Alert:
    """
    Represents an alert generated from accumulated evidence.
    """
    # The profile (IP) that generated this alert
    profile: ProfileID
    # The timewindow during which the evidence was detected
    timewindow: TimeWindow
    # The accumulated threat level that triggered the alert
    threat_level: ThreatLevel
    # IDs of evidence that caused this alert
    correl_id: List[str] = field(default_factory=list)
    # The alert's unique ID
    id: str = field(default_factory=lambda: str(uuid4()))
    # Human-readable description
    description: str = ""
    # The attacker IP (same as profile IP in most cases)
    attacker: str = ""
    # The victim IP
    victim: str = ""

    def __post_init__(self):
        if isinstance(self.profile, str):
            from smartshield_files.core.structures.evidence import ProfileID
            self.profile = ProfileID(ip=self.profile.split("_")[-1])
        if not self.attacker and self.profile:
            self.attacker = str(self.profile).split("_")[-1]


def alert_to_dict(alert: Alert) -> dict:
    """Convert an Alert dataclass to a dictionary."""
    d = asdict(alert)
    # Convert nested dataclasses
    d["profile"] = str(alert.profile)
    d["timewindow"] = str(alert.timewindow)
    d["threat_level"] = str(alert.threat_level)
    return d


def dict_to_alert(data: dict) -> Alert:
    """Convert a dictionary to an Alert dataclass."""
    from smartshield_files.core.structures.evidence import (
        ProfileID, TimeWindow, ThreatLevel,
    )
    profile = data.get("profile", "")
    if isinstance(profile, str):
        ip = profile.split("_")[-1]
        profile = ProfileID(ip=ip)
    tw = data.get("timewindow", "timewindow1")
    if isinstance(tw, str):
        tw_num = int(tw.replace("timewindow", "")) if "timewindow" in tw else 1
        tw = TimeWindow(number=tw_num)
    tl = data.get("threat_level", "high")
    if isinstance(tl, str):
        tl = ThreatLevel[tl.upper()]

    return Alert(
        profile=profile,
        timewindow=tw,
        threat_level=tl,
        correl_id=data.get("correl_id", []),
        id=data.get("id", str(uuid4())),
        description=data.get("description", ""),
        attacker=data.get("attacker", ""),
        victim=data.get("victim", ""),
    )
