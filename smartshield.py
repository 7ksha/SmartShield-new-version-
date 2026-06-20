

from __future__ import print_function

import os
import sys
import time
import warnings

from smartshield.main import Main
from smartshield.daemon import Daemon


# Ignore warnings on CPU from tensorflow
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
# Ignore warnings in general
warnings.filterwarnings("ignore")


####################
# Main
####################
if __name__ == "__main__":
    if sys.version_info[0] < 3:
        sys.exit("smartshield can only run on python3+ .. Stopping.")

    smartshield = Main()

    if smartshield.args.stopdaemon:
        # -S is provided
        daemon_status: dict = Daemon(smartshield).stop()
        # it takes about 5 seconds for the stop_smartshield msg
        # to arrive in the channel, so give smartshield time to stop
        time.sleep(5)
        if daemon_status["stopped"]:
            print("Daemon stopped.")
        else:
            print(daemon_status["error"])

    elif smartshield.args.daemon:
        print("smartshield daemon starting..")
        Daemon(smartshield).start()
    else:
        # interactive mode
        smartshield.start()
