
from abc import ABC, abstractmethod


class IInputType(ABC):
    """Interface for input type handlers."""

    @abstractmethod
    def read(self, input_information):
        """Read the given input and yield flows."""
