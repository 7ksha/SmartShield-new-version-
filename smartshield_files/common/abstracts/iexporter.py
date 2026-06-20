
from abc import ABC, abstractmethod


class IExporter(ABC):
    """Interface for alert exporters (Slack, STIX, etc.)."""

    name = "IExporter"

    @abstractmethod
    def export(self, alert: dict):
        """Export the given alert."""
