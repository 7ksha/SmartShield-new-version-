
from abc import ABC, abstractmethod


class IPerformanceProfiler(ABC):
    """Interface for performance profilers (CPU, memory)."""

    @abstractmethod
    def start(self):
        """Start profiling."""

    @abstractmethod
    def stop(self):
        """Stop profiling and return results."""
