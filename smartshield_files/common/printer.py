

from smartshield_files.core.output import Output


class Printer:
    """
    Proxy printer that sends output through the Output process
    for centralized logging and terminal display.
    """

    def __init__(self, logger: Output, name: str):
        self.logger = logger
        self.name = name

    def print(self, text, verbose: int = 1, debug: int = 0):
        """
        Send text to the output process.
        - verbose: verbosity level (1+ means it will be shown)
        - debug: debug level (0 = no debug, higher = more debug info)
        """
        try:
            # If logger has a print method, use it
            if self.logger and hasattr(self.logger, "print"):
                self.logger.print(f"[{self.name}] {text}", verbose, debug)
            else:
                print(f"[{self.name}] {text}")
        except Exception:
            # Fallback if output process is down
            print(f"[{self.name}] {text}")
