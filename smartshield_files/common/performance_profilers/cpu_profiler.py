
"""CPU profiler using viztracer if available."""
import os


class CPUProfiler:
    """CPU profiler for SmartShield."""

    def __init__(self, mode="dev", output_dir="output/"):
        self.mode = mode
        self.output_dir = output_dir
        self.profiler = None

    def start(self):
        """Start CPU profiling."""
        try:
            from viztracer import VizTracer
            self.profiler = VizTracer()
            self.profiler.start()
        except ImportError:
            pass

    def stop(self):
        """Stop CPU profiling and save results."""
        if self.profiler:
            self.profiler.stop()
            path = os.path.join(self.output_dir, "cpu_profile.json")
            self.profiler.save(path)
            return path
        return None
