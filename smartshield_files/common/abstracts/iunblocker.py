
from abc import ABC, abstractmethod


class IUnblocker(ABC):
    """Interface for IP unblockers."""

    @abstractmethod
    def unblock(self, ip: str):
        """Unblock the given IP."""

    @abstractmethod
    def unblock_all(self):
        """Unblock all previously blocked IPs."""
