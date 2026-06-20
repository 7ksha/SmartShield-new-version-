
"""Memory profiler using memory_profiler if available."""
import os


class MemoryProfiler:
    """Memory profiler for SmartShield."""

    def __init__(self, mode="live", output_dir="output/"):
        self.mode = mode
        self.output_dir = output_dir

    def start(self):
        """Start memory profiling."""
        pass

    def stop(self):
        """Stop memory profiling and return results."""
        return None

    def get_usage(self):
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / (1024 * 1024)
        except ImportError:
            return 0.0
