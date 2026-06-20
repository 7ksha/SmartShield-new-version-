

from abc import ABC, abstractmethod


class ICore(ABC):
    """Interface for core components."""

    @abstractmethod
    def init(self):
        """Initialize the core component."""

    @abstractmethod
    def run(self):
        """Run the core component."""
