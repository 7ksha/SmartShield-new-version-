from typing import Optional

from modules.fidesModule.model.aliases import Target
from modules.fidesModule.model.threat_intelligence import smartshieldThreatIntelligence


class ThreatIntelligenceDatabase:
    """Database that stores threat intelligence data."""

    def get_for(self, target: Target) -> Optional[smartshieldThreatIntelligence]:
        """Returns threat intelligence for given target or None if there are no data."""
        raise NotImplemented()
