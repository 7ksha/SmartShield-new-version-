
from abc import ABC, abstractmethod


class IFlowalertsAnalyzer(ABC):
    """Interface for flow alerts analyzers."""

    @abstractmethod
    def analyze(self, profileid: str, twid: str, flow: dict):
        """Analyze the given flow for the profile/timewindow."""
