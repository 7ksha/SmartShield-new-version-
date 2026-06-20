

import multiprocessing
import sys
import os
import time
import json

# so that smartshield can be imported from any directory
sys.path.insert(0, os.getcwd())

from smartshield_files.core.database.database_manager import DBManager
from smartshield_files.common.printer import Printer


class IModule(multiprocessing.Process):
    """
    An IModule process. This is the template class for every SmartShield module.
    The 'name' attribute MUST be defined in each module. It is the public name
    of the module, used for disabling modules etc.
    
    Lifecycle:
        1. __init__()      - Set up the process, create DBManager
        2. init()          - Subscribe to channels (called in run())
        3. pre_main()      - One-time initialization before main loop
        4. main()          - Called repeatedly in a loop
        5. shutdown_gracefully() - Cleanup when stopping
    """

    name = "IModule"
    description = "Template interface for a SmartShield module"

    def __init__(
        self,
        logger,
        output_dir,
        redis_port,
        termination_event,
        args,
        conf,
        main_pid,
        bloom_filters_man,
    ):
        self.logger = logger
        self.output_dir = output_dir
        self.args = args
        self.conf = conf
        self.main_pid = main_pid
        self.bloom_filters_man = bloom_filters_man
        self.printer = Printer(logger, self.name)
        multiprocessing.Process.__init__(self)
        self.termination_event = termination_event
        self.daemon = True
        try:
            # Some modules may not need redis (e.g. testing scenarios)
            self.db = DBManager(
                self.logger,
                self.output_dir,
                redis_port,
                self.conf,
                self.main_pid,
            )
        except Exception as e:
            self.print(f"Error connecting to DB in {self.name}: {e}", 0, 1)
            self.db = None

    def print(self, text: str, verbose: int = 1, debug: int = 0):
        """
        Proxy print method that sends output through the Printer
        to the output process for centralized logging.
        """
        try:
            self.printer.print(text, verbose, debug)
        except Exception:
            # Fallback if printer/output isn't available
            print(f"[{self.name}] {text}")

    def get_msg(self, channel_name, timeout=0.0000001):
        """
        Get a message from the given subscribed channel.
        Returns the message dict or None if no message is available.
        
        The channel must have been subscribed in init() and stored in
        self.channels dict.
        """
        try:
            channel_obj = self.channels.get(channel_name)
            if not channel_obj:
                return None
            return self.db.get_message(channel_obj, timeout=timeout)
        except Exception:
            return None

    def run(self):
        try:
            error: int = self.init()
            if error or (error is not None and error != 0):
                self.print(
                    f"Module {self.name} initialization failed with error "
                    f"code {error}. Stopping."
                )
                return
            self.pre_main()
            while True:
                if self.termination_event.is_set():
                    self.shutdown_gracefully()
                    return
                try:
                    error: int = self.main()
                except Exception:
                    error = 1
                if error:
                    self.shutdown_gracefully()
                    return
        except KeyboardInterrupt:
            self.shutdown_gracefully()
        except Exception:
            self.shutdown_gracefully()

    def init(self):
        """
        Initialize the module: subscribe to channels, read configs, etc.
        Returns an error code (int) or None/0 on success.
        """

    def pre_main(self):
        """
        Run once before the main() loop.
        Good for: dropping root privs, checking API keys, etc.
        """

    def main(self):
        """
        Main loop function. Called repeatedly.
        Should return 0/None on success, non-zero on error to stop the module.
        """

    def shutdown_gracefully(self):
        """
        Cleanup when the module is stopping.
        Override to save models, flush buffers, etc.
        """
