
import platform
import sys
import os
import shutil
import json
import subprocess
from typing import Dict
import time
from threading import Lock

from smartshield_files.common.abstracts.imodule import IModule
from smartshield_files.common.smartshield_utils import utils
from .exec_iptables_cmd import exec_iptables_command
from modules.blocking.unblocker import Unblocker


OUTPUT_TO_DEV_NULL = ">/dev/null 2>&1"


class Blocking(IModule):
    """Data should be passed to this module as a json encoded python dict,
    by default this module flushes all smartshieldBlocking chains before it starts"""

    # Name: short name of the module. Do not use spaces
    name = "Blocking"
    description = "Block malicious IPs connecting to this device"

    def init(self):
        self.c1 = self.db.subscribe("new_blocking")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_blocking": self.c1,
            "tw_closed": self.c2,
        }
        if platform.system() == "Darwin":
            self.print("Mac OS blocking is not supported yet.")
            sys.exit()

        self.firewall = self._determine_linux_firewall()
        self.sudo = utils.get_sudo_according_to_env()
        self._init_chains_in_firewall()
        self.blocking_log_path = os.path.join(self.output_dir, "blocking.log")
        self.blocking_logfile_lock = Lock()
        # clear it
        try:
            open(self.blocking_log_path, "w").close()
        except FileNotFoundError:
            pass
        self.last_closed_tw = None

        # ── OT-safe blocking: load protected device list ─────────────────────
        self._ot_protected_ips = self._load_ot_protected_ips()
        if self._ot_protected_ips:
            self.print(
                f"OT-safe mode: {len(self._ot_protected_ips)} protected OT "
                f"device IPs will never be blocked.",
                verbose=1,
            )

        self.ap_info: None | Dict[str, str] = self.db.get_ap_info()
        self.is_running_in_ap_mode = True if self.ap_info else False

    def log(self, text: str):
        """Logs the given text to the blocking log file"""
        with self.blocking_logfile_lock:
            with open(self.blocking_log_path, "a") as f:
                now = time.time()
                human_readable_datetime = utils.convert_ts_format(
                    now, utils.alerts_format
                )
                f.write(f"{human_readable_datetime} - {text}\n")

    def _determine_linux_firewall(self):
        """Returns the currently installed firewall and installs iptables if
        none was found"""

        if shutil.which("iptables"):
            # comes pre installed in docker
            return "iptables"
        else:
            # no firewall installed
            # user doesn't have a firewall
            self.print(
                "iptables is not installed. Blocking module is quitting."
            )
            sys.exit()

    def _get_cmd_output(self, command):
        """Executes a command and returns the output"""
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode("utf-8")

    def _init_chains_in_firewall(self):
        """For linux: Adds a chain to iptables or a table to nftables called
        smartshieldBlocking where all the rules will reside"""

        if self.firewall != "iptables":
            return

        # delete any pre existing smartshieldBlocking rules that may conflict before
        # adding a new one
        # self.delete_iptables_chain()
        self.print('Executing "sudo iptables -N smartshieldBlocking"', 6, 0)
        # Add a new chain to iptables
        os.system(
            f"{self.sudo} iptables -N smartshieldBlocking {OUTPUT_TO_DEV_NULL}"
        )

        # Check if we're already redirecting to smartshieldBlocking chain
        input_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL INPUT"
        )
        output_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL OUTPUT"
        )
        forward_chain_rules = self._get_cmd_output(
            f"{self.sudo} iptables -nvL FORWARD"
        )
        # Redirect the traffic from all other chains to smartshieldBlocking so rules
        # in any pre-existing chains dont override it
        # -I to insert smartshieldBlocking at the top of the INPUT, OUTPUT and
        # FORWARD chains
        if "smartshieldBlocking" not in input_chain_rules:
            os.system(
                f"{self.sudo} iptables -I INPUT -j smartshieldBlocking "
                f"{OUTPUT_TO_DEV_NULL}"
            )
        if "smartshieldBlocking" not in output_chain_rules:
            os.system(
                f"{self.sudo} iptables -I OUTPUT -j smartshieldBlocking "
                f"{OUTPUT_TO_DEV_NULL}"
            )
        if "smartshieldBlocking" not in forward_chain_rules:
            os.system(
                f"{self.sudo} iptables -I FORWARD -j smartshieldBlocking"
                f" {OUTPUT_TO_DEV_NULL}"
            )


    def _load_ot_protected_ips(self) -> set:
        """
        Load the list of OT device IPs that must never be blocked.
        These are PLCs, HMIs, SCADA servers, RTUs etc.
        File: config/ot_protected_devices.conf
        One IP/CIDR per line. Lines starting with # are comments.
        """
        import ipaddress as _ip
        path = "config/ot_protected_devices.conf"
        ips = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Support CIDR notation: expand to individual check below
                    ips.add(line.split()[0])
        except FileNotFoundError:
            pass
        return ips

    def _is_ot_protected(self, ip: str) -> bool:
        """
        Returns True if ip is in the OT protected devices list.
        Supports exact IP match and CIDR range containment.
        """
        import ipaddress as _ip
        try:
            addr = _ip.ip_address(ip)
        except ValueError:
            return False
        for entry in self._ot_protected_ips:
            try:
                if "/" in entry:
                    if addr in _ip.ip_network(entry, strict=False):
                        return True
                else:
                    if addr == _ip.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    def _is_ip_already_blocked(self, ip) -> bool:
        """Checks if ip is already blocked or not using iptables"""
        command = f"{self.sudo} iptables -L smartshieldBlocking -v -n"
        # Execute command
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        result = result.stdout.decode("utf-8")
        return ip in result

    def _block_ip(self, ip_to_block: str, flags: Dict[str, str]) -> bool:
        """
        This function determines the user's platform and firewall and calls
        the appropriate function to add the rules to the used firewall.
        By default this function blocks all traffic from and to the given ip.
        and it Blocks private IPs on the given interface, and block public
        IPs on all interfaces
        returns true if the ip is successfully blocked
        """


        # ── OT-safe blocking guard ────────────────────────────────────────────
        if self._is_ot_protected(ip_to_block):
            txt = (
                f"[OT-SAFE] Blocking suppressed for protected OT device "
                f"{ip_to_block}. Evidence recorded but no iptables rule added. "
                f"Investigate manually."
            )
            self.print(txt, verbose=1)
            self.log(txt)
            return False
        # ─────────────────────────────────────────────────────────────────────

        if self.firewall != "iptables":
            return

        if not isinstance(ip_to_block, str):
            return False

        # Make sure ip isn't already blocked before blocking
        if self._is_ip_already_blocked(ip_to_block):
            return False

        from_ = flags.get("from_")
        to = flags.get("to")
        dport = flags.get("dport")
        sport = flags.get("sport")
        protocol = flags.get("protocol")
        interface = flags.get("interface")
        # Set the default behaviour to block all traffic from and to an ip
        if from_ is None and to is None:
            from_, to = True, True
        # This dictionary will be used to construct the rule
        options = {
            "protocol": f" -p {protocol}" if protocol is not None else "",
            "dport": f" --dport {dport}" if dport is not None else "",
            "sport": f" --sport {sport}" if sport is not None else "",
        }

        if utils.is_private_ip(ip_to_block) and interface:
            # block all ingoing AND outgoing packet on the given interface
            options.update(
                {
                    "interface": f" -i {interface} -o {interface}",
                }
            )

        blocked = False
        if from_:
            # Add rule to block traffic from source ip_to_block (-s)
            blocked = exec_iptables_command(
                self.sudo,
                action="insert",
                ip_to_block=ip_to_block,
                flag="-s",
                options=options,
            )
            if blocked:
                txt = f"Blocked all traffic from: {ip_to_block}"
                self.print(txt)
                self.log(txt)

        if to:
            # Add rule to block traffic to ip_to_block (-d)
            blocked = exec_iptables_command(
                self.sudo,
                action="insert",
                ip_to_block=ip_to_block,
                flag="-d",
                options=options,
            )
            if blocked:
                txt = f"Blocked all traffic to: {ip_to_block}"
                self.print(txt)
                self.log(f"Blocked all traffic to: {ip_to_block}")
                self.db.set_blocked_ip(ip_to_block)
        return blocked

    def shutdown_gracefully(self):
        self.unblocker.unblocker_thread.join(30)
        if self.unblocker.unblocker_thread.is_alive():
            self.print("Problem shutting down unblocker thread.")

    def pre_main(self):
        self.unblocker = Unblocker(
            self.db, self.sudo, self.should_stop, self.logger, self.log
        )

    def main(self):
        if msg := self.get_msg("new_blocking"):
            # message['data'] in the new_blocking channel is a dictionary that contains
            # the ip and the blocking options
            # Example of the data dictionary to block or unblock an ip:
            # (notice you have to specify from,to,dport,sport,protocol or at
            # least 2 of them when unblocking)
            #   blocking_data = {
            #       "ip"       : "0.0.0.0"
            #       "tw"       : 1
            #       "block"    : True to block  - False to unblock
            #       "from"     : True to block traffic from ip (default) - False does nothing
            #       "to"       : True to block traffic to ip  (default)  - False does nothing
            #       "dport"    : Optional destination port number
            #       "sport"    : Optional source port number
            #       "protocol" : Optional protocol
            #   }
            # Example of passing blocking_data to this module:
            #   blocking_data = json.dumps(blocking_data)
            #   self.db.publish('new_blocking', blocking_data )

            data = json.loads(msg["data"])
            ip = data.get("ip")
            tw: int = data.get("tw")
            block = data.get("block")

            flags = {
                "from_": data.get("from"),
                "to": data.get("to"),
                "dport": data.get("dport"),
                "sport": data.get("sport"),
                "protocol": data.get("protocol"),
                "interface": data.get("interface"),
            }
            if block:
                self._block_ip(ip, flags)
            # whether this ip is blocked now, or was already blocked, make an
            # unblocking request to either extend its
            # blocking period, or block it until the next timewindow is over.
            self.unblocker.unblock_request(ip, tw, flags)

        if msg := self.get_msg("tw_closed"):
            # this channel receives requests for closed tws for every ip
            # smartshield sees.
            # if smartshield saw 3 ips, this channel will receive 3 msgs with tw1
            # as closed. we're not interested in the ips, we just wanna
            # know when smartshield advances to the next tw.
            profileid_tw = msg["data"].split("_")
            twid = profileid_tw[-1]
            if self.last_closed_tw != twid:
                self.last_closed_tw = twid
                self.unblocker.update_requests()
