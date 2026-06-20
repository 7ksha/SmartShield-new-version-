

from abc import ABC, abstractmethod


class IObserver(ABC):
    """Observer pattern interface used by the output process."""

    @abstractmethod
    def update(self, msg: str):
        """Called when the observed subject has a new message."""
