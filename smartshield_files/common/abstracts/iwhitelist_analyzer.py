
from abc import ABC, abstractmethod


class IWhitelistAnalyzer(ABC):
    """Interface for whitelist analyzers."""

    @abstractmethod
    def is_whitelisted(self, ip: str) -> bool:
        """Check if the given IP is whitelisted."""
