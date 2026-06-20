"""
SmartShield OT/ICS Detection Module
====================================
Detects attacks targeting Operational Technology (OT) and Industrial Control
Systems (ICS) environments:

  - Modbus/TCP  (port 502)  : scan, flood, unauthorized write, illegal function
  - Siemens S7Comm (port 102): job flood, unauthorized read/write, PLC STOP
  - DNP3        (port 20000): flood, unauthorized function
  - OPC-UA      (port 4840) : handled via generic anomaly
  - PROFINET DCP (port 34964): discovery flood
  - EtherNet/IP CIP (port 44818): explicit message flood
  - Time-sync attacks        : NTP spoofing, PTP grandmaster spoofing

Architecture note
-----------------
This module subscribes to ``new_flow`` (every Zeek conn.log entry) and
``new_notice`` (Zeek notice.log).  Zeek OT protocol parsers are loaded via
``zeek-scripts/ot_protocols.zeek`` and publish additional detail via Redis
channels ``new_modbus``, ``new_s7comm``, ``new_dnp3``.

OT-safe blocking
----------------
IPs listed in ``config/ot_protected_devices.conf`` (PLCs, HMIs, SCADA servers)
will NEVER be passed to the blocking module — only evidence is generated.
External/IT-side IPs that attack OT devices are still blocked normally.
"""

import json
import ipaddress
import time
from collections import defaultdict
from typing import Dict, List, Set

from smartshield_files.common.abstracts.imodule import IModule
from smartshield_files.common.parsers.config_parser import ConfigParser
from smartshield_files.common.smartshield_utils import utils
from smartshield_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    Victim,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Proto,
)


# ── OT well-known ports ─────────────────────────────────────────────────────
MODBUS_PORT = 502
S7COMM_PORT = 102
DNP3_PORT = 20000
OPCUA_PORT = 4840
PROFINET_DCP_PORT = 34964
CIP_PORT = 44818
NTP_PORT = 123
PTP_PORT = 319          # IEEE 1588 event messages

OT_PORTS: Set[int] = {
    MODBUS_PORT, S7COMM_PORT, DNP3_PORT, OPCUA_PORT,
    PROFINET_DCP_PORT, CIP_PORT,
}

# Function codes considered "write" in Modbus
MODBUS_WRITE_FUNCTION_CODES: Set[int] = {
    5,   # Write Single Coil
    6,   # Write Single Register
    15,  # Write Multiple Coils
    16,  # Write Multiple Registers
    22,  # Mask Write Register
    23,  # Read/Write Multiple Registers
}

# S7 function codes that indicate a STOP or dangerous command
S7_DANGEROUS_FUNCTIONS: Set[int] = {
    0x29,   # PLC Stop
    0x28,   # PLC Start (also dangerous if unauthorized)
    0x00,   # CPU services (control plane)
}


class OTDetection(IModule):
    """OT/ICS intrusion detection module for SmartShield."""

    name = "OT Detection"
    description = (
        "Detects attacks on OT/ICS environments: Modbus, S7Comm, DNP3, "
        "PROFINET, CIP, NTP/PTP time-sync attacks, PLC mode-switching, "
        "valve/motor cycling, and more."
    )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def init(self):
        # db.subscribe() returns False for any channel that isn't registered
        # in the database's supported_channels. Calling get_msg() on a False
        # handle raises 'bool' object has no attribute 'get_message' and kills
        # the module, so only keep channels that subscribed successfully.
        wanted = [
            "new_flow", "new_notice", "new_modbus", "new_s7comm", "new_dnp3",
        ]
        self.channels = {}
        for ch in wanted:
            handle = self.db.subscribe(ch)
            if handle:
                self.channels[ch] = handle
            else:
                self.print(
                    f"Channel '{ch}' is not available (not registered) - "
                    f"skipping it.",
                    verbose=1,
                )

        self._read_configuration()

        # Per-timewindow state counters keyed by (profileid, twid)
        # Modbus connection tracking: src_ip -> list of timestamps
        self._modbus_conns: Dict[str, List[float]] = defaultdict(list)
        # Modbus write attempts: (src, dst) -> count
        self._modbus_writes: Dict[tuple, int] = defaultdict(int)
        # S7 job requests: src_ip -> list of timestamps
        self._s7_jobs: Dict[str, List[float]] = defaultdict(list)
        # DNP3 fragments: src_ip -> list of timestamps
        self._dnp3_frags: Dict[str, List[float]] = defaultdict(list)
        # PROFINET DCP discovery: src_ip -> list of timestamps
        self._profinet_dcp: Dict[str, List[float]] = defaultdict(list)
        # CIP messages: src_ip -> list of timestamps
        self._cip_msgs: Dict[str, List[float]] = defaultdict(list)
        # PLC mode-switch tracking: dst_ip -> [timestamps]
        self._plc_mode_switches: Dict[str, List[float]] = defaultdict(list)
        # NTP responses: src_ip -> list of timestamps (to detect floods/spoofs)
        self._ntp_responses: Dict[str, List[float]] = defaultdict(list)
        # Track which (src, dst) pairs already generated evidence this TW
        # to avoid duplicate spam
        self._alerted: Set[str] = set()
        # Counter for periodic cleanup of _alerted set
        self._alerted_cleanup_counter: int = 0

        self.print(
            f"OT Detection started. Protecting {len(self._ot_protected_ips)} "
            f"OT device IPs. Monitoring ports: {sorted(OT_PORTS)}",
            verbose=1,
        )

    def pre_main(self):
        utils.drop_root_privs_permanently()

    # ── Main loop ────────────────────────────────────────────────────────────

    def main(self):
        # Process Zeek conn.log flows
        if "new_flow" in self.channels and (msg := self.get_msg("new_flow")):
            self._handle_flow(msg["data"])

        # Process Zeek notice.log entries
        if "new_notice" in self.channels and (msg := self.get_msg("new_notice")):
            self._handle_notice(msg["data"])

        # Process Modbus-specific events (from zeek OT parser)
        if "new_modbus" in self.channels and (msg := self.get_msg("new_modbus")):
            self._handle_modbus(msg["data"])

        # Process S7Comm events
        if "new_s7comm" in self.channels and (msg := self.get_msg("new_s7comm")):
            self._handle_s7comm(msg["data"])

        # Process DNP3 events
        if "new_dnp3" in self.channels and (msg := self.get_msg("new_dnp3")):
            self._handle_dnp3(msg["data"])

        # Periodic cleanup of the _alerted set to prevent memory growth
        self._alerted_cleanup_counter += 1
        if self._alerted_cleanup_counter >= 10000:
            self._alerted.clear()
            self._alerted_cleanup_counter = 0

    # ── Configuration ────────────────────────────────────────────────────────

    def _read_configuration(self):
        conf = ConfigParser()
        # Load OT-protected device IPs from config file
        self._ot_protected_ips: Set[str] = self._load_ot_devices(conf)
        # Load whitelisted Modbus masters (IPs allowed to read/write PLCs)
        self._modbus_authorized_masters: Set[str] = \
            self._load_modbus_masters(conf)
        # Load whitelisted S7 masters (IPs allowed to access S7 PLCs)
        # Falls back to Modbus authorized masters if no separate S7 list
        self._s7_authorized_masters: Set[str] = \
            self._load_s7_masters(conf) or self._modbus_authorized_masters.copy()

        # Detection thresholds (configurable in smartshield.yaml)
        raw = conf.read_configuration("ot_detection", "modbus_flood_threshold",
                                      "20")
        self._modbus_flood_threshold = int(raw)

        raw = conf.read_configuration("ot_detection", "s7_job_flood_threshold",
                                      "50")
        self._s7_job_threshold = int(raw)

        raw = conf.read_configuration("ot_detection", "dnp3_flood_threshold",
                                      "100")
        self._dnp3_flood_threshold = int(raw)

        raw = conf.read_configuration("ot_detection", "profinet_dcp_threshold",
                                      "50")
        self._profinet_dcp_threshold = int(raw)

        raw = conf.read_configuration("ot_detection", "cip_flood_threshold",
                                      "100")
        self._cip_threshold = int(raw)

        raw = conf.read_configuration("ot_detection",
                                      "plc_mode_switch_threshold", "5")
        self._plc_mode_switch_threshold = int(raw)

        raw = conf.read_configuration("ot_detection", "flood_window_seconds",
                                      "60")
        self._flood_window = int(raw)

        raw = conf.read_configuration("ot_detection",
                                      "connection_min_flood_packets", "200")
        self._min_flood_packets = int(raw)

        raw = conf.read_configuration("ot_detection",
                                      "packet_rate_threshold", "50")
        self._packet_rate_threshold = float(raw)

    @staticmethod
    def _ot_port_evidence(dport: int):
        """Map an OT destination port to its flood EvidenceType + label."""
        mapping = {
            MODBUS_PORT: (EvidenceType.OT_MODBUS_CONNECTION_FLOOD, "Modbus"),
            S7COMM_PORT: (EvidenceType.OT_S7COMM_JOB_FLOOD, "S7Comm"),
            DNP3_PORT: (EvidenceType.OT_DNP3_FLOOD, "DNP3"),
            PROFINET_DCP_PORT: (EvidenceType.OT_PROFINET_DCP_FLOOD, "PROFINET"),
            CIP_PORT: (EvidenceType.OT_CIP_MESSAGE_FLOOD, "CIP"),
            NTP_PORT: (EvidenceType.OT_NTP_TIME_SYNC_ATTACK, "NTP"),
            PTP_PORT: (EvidenceType.OT_PTP_SPOOFING, "PTP"),
        }
        return mapping.get(dport, (EvidenceType.OT_PROTOCOL_ANOMALY, "OT"))

    @staticmethod
    def _load_ot_devices(conf) -> Set[str]:
        """
        Read config/ot_protected_devices.conf.
        Format: one IP or CIDR per line, lines starting with # are comments.
        """
        path = conf.read_configuration(
            "ot_detection", "ot_devices_file",
            "config/ot_protected_devices.conf"
        )
        ips: Set[str] = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ips.add(line.split()[0])
        except FileNotFoundError:
            pass
        return ips

    @staticmethod
    def _load_modbus_masters(conf) -> Set[str]:
        """Read config/modbus_authorized_masters.conf"""
        path = conf.read_configuration(
            "ot_detection", "modbus_masters_file",
            "config/modbus_authorized_masters.conf"
        )
        ips: Set[str] = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.add(line.split()[0])
        except FileNotFoundError:
            pass
        return ips

    @staticmethod
    def _load_s7_masters(conf) -> Set[str]:
        """
        Read config/s7_authorized_masters.conf if it exists.
        Falls back to empty set if not found, so caller can use
        modbus_authorized_masters as fallback.
        """
        path = conf.read_configuration(
            "ot_detection", "s7_masters_file",
            "config/s7_authorized_masters.conf"
        )
        ips: Set[str] = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.add(line.split()[0])
        except FileNotFoundError:
            pass
        return ips

    # ── Flow-level OT detection ──────────────────────────────────────────────

    def _handle_flow(self, raw: str):
        """
        Analyse a Zeek conn.log flow for OT-relevant patterns.
        Called for every network flow.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        # new_flow messages wrap the actual flow fields in a nested "flow"
        # dict (asdict(flow)), while profileid/twid live at the top level.
        # See profile_handler.add_flow(): {"profileid","twid","flow":{...}}.
        profileid: str = data.get("profileid", "")
        twid: str = data.get("twid", "")
        flow: dict = data.get("flow", {})
        if not isinstance(flow, dict):
            return

        saddr: str = flow.get("saddr", "")
        daddr: str = flow.get("daddr", "")
        dport: int = int(flow.get("dport", 0) or 0)
        proto: str = (flow.get("proto") or "").lower()
        uid: str = flow.get("uid", "")
        timestamp: str = flow.get("starttime", "")
        state: str = flow.get("state", "")

        if not (saddr and daddr and dport and uid):
            return

        now = time.time()

        # ── High-volume / high-rate single-connection flood ──────────────
        # A flood that rides ONE long-lived TCP/UDP connection is logged by
        # Zeek as a single conn.log flow, so the per-connection counters
        # below never reach their thresholds. Catch it using the packet
        # counts and duration Zeek already records for the flow.
        if dport in OT_PORTS or dport in (NTP_PORT, PTP_PORT):
            flow_pkts = (int(flow.get("spkts", 0) or 0)
                         + int(flow.get("dpkts", 0) or 0))
            try:
                dur = float(flow.get("dur", 0) or 0)
            except (TypeError, ValueError):
                dur = 0.0
            rate = (flow_pkts / dur) if dur > 0 else float("inf")
            if (flow_pkts >= self._min_flood_packets
                    and rate >= self._packet_rate_threshold):
                alert_key = f"vol_flood:{saddr}:{daddr}:{dport}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    ev_type, proto_name = self._ot_port_evidence(dport)
                    rate_str = (f"{rate:.0f} pkts/s" if dur > 0
                                else "unknown rate")
                    self._set_evidence(
                        ev_type=ev_type,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.9,
                        description=(
                            f"{proto_name} request flood from {saddr} to "
                            f"{daddr}:{dport}: {flow_pkts} packets in a single "
                            f"connection ({rate_str}) — high-volume {proto_name} "
                            f"session targeting an OT service."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.UDP if proto == "udp" else Proto.TCP,
                    )

        # ── Modbus flood detection ─────────────────────────────────────────
        if dport == MODBUS_PORT and proto == "tcp":
            self._modbus_conns[saddr].append(now)
            self._modbus_conns[saddr] = [
                t for t in self._modbus_conns[saddr]
                if now - t <= self._flood_window
            ]
            count = len(self._modbus_conns[saddr])

            if count >= self._modbus_flood_threshold:
                alert_key = f"modbus_flood:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_MODBUS_CONNECTION_FLOOD,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.9,
                        description=(
                            f"Modbus connection flood from {saddr} to "
                            f"{daddr}: {count} connections in "
                            f"{self._flood_window}s (threshold "
                            f"{self._modbus_flood_threshold})."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

            # Unauthorized Modbus access (from unknown master)
            if (self._modbus_authorized_masters
                    and saddr not in self._modbus_authorized_masters
                    and daddr in self._ot_protected_ips):
                alert_key = f"modbus_unauth:{saddr}:{daddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_UNAUTHORIZED_MODBUS_ACCESS,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.85,
                        description=(
                            f"Unauthorized Modbus access: {saddr} is not in "
                            f"the authorized Modbus master list but connected "
                            f"to OT device {daddr}:502."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

        # ── S7Comm job flood ───────────────────────────────────────────────
        if dport == S7COMM_PORT and proto == "tcp":
            self._s7_jobs[saddr].append(now)
            self._s7_jobs[saddr] = [
                t for t in self._s7_jobs[saddr]
                if now - t <= self._flood_window
            ]
            count = len(self._s7_jobs[saddr])

            if count >= self._s7_job_threshold:
                alert_key = f"s7_flood:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_S7COMM_JOB_FLOOD,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.9,
                        description=(
                            f"Siemens S7Comm job flood from {saddr} to "
                            f"{daddr}: {count} requests in "
                            f"{self._flood_window}s."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

            # S7 from unauthorized source targeting a protected OT IP
            # FIX: Use _s7_authorized_masters instead of _modbus_authorized_masters
            if (self._s7_authorized_masters
                    and saddr not in self._s7_authorized_masters
                    and daddr in self._ot_protected_ips):
                alert_key = f"s7_unauth:{saddr}:{daddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_S7COMM_UNAUTHORIZED_READ,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description=(
                            f"Unauthorized S7Comm access from {saddr} to "
                            f"OT device {daddr}:102."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

        # ── DNP3 flood ─────────────────────────────────────────────────────
        if dport == DNP3_PORT and proto in ("tcp", "udp"):
            self._dnp3_frags[saddr].append(now)
            self._dnp3_frags[saddr] = [
                t for t in self._dnp3_frags[saddr]
                if now - t <= self._flood_window
            ]
            count = len(self._dnp3_frags[saddr])

            if count >= self._dnp3_flood_threshold:
                alert_key = f"dnp3_flood:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_DNP3_FLOOD,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.85,
                        description=(
                            f"DNP3 request flood from {saddr} to {daddr}: "
                            f"{count} requests in {self._flood_window}s."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

        # ── PROFINET DCP flood ─────────────────────────────────────────────
        if dport == PROFINET_DCP_PORT:
            self._profinet_dcp[saddr].append(now)
            self._profinet_dcp[saddr] = [
                t for t in self._profinet_dcp[saddr]
                if now - t <= self._flood_window
            ]
            count = len(self._profinet_dcp[saddr])

            if count >= self._profinet_dcp_threshold:
                alert_key = f"profinet_flood:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_PROFINET_DCP_FLOOD,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.8,
                        description=(
                            f"PROFINET DCP discovery flood from {saddr}: "
                            f"{count} requests in {self._flood_window}s — "
                            f"can overwhelm industrial devices."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.UDP,
                    )

        # ── EtherNet/IP CIP message flood ──────────────────────────────────
        if dport == CIP_PORT and proto == "tcp":
            self._cip_msgs[saddr].append(now)
            self._cip_msgs[saddr] = [
                t for t in self._cip_msgs[saddr]
                if now - t <= self._flood_window
            ]
            count = len(self._cip_msgs[saddr])

            if count >= self._cip_threshold:
                alert_key = f"cip_flood:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_CIP_MESSAGE_FLOOD,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.85,
                        description=(
                            f"EtherNet/IP CIP explicit message flood from "
                            f"{saddr} to {daddr}: {count} messages in "
                            f"{self._flood_window}s."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.TCP,
                    )

        # ── NTP spoofing/flood ─────────────────────────────────────────────
        if dport == NTP_PORT and proto == "udp":
            self._ntp_responses[saddr].append(now)
            self._ntp_responses[saddr] = [
                t for t in self._ntp_responses[saddr]
                if now - t <= 10   # 10-second window for NTP
            ]
            # If a single source sends > 5 NTP responses/10s it is anomalous
            if len(self._ntp_responses[saddr]) > 5:
                alert_key = f"ntp_spoof:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_NTP_TIME_SYNC_ATTACK,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.75,
                        description=(
                            f"Possible NTP time-sync attack: {saddr} sent "
                            f"{len(self._ntp_responses[saddr])} NTP responses "
                            f"in 10s — may be NTP spoofing targeting OT clocks."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.UDP,
                    )

        # ── PTP (IEEE 1588) grandmaster spoofing ──────────────────────────
        if dport == PTP_PORT and proto == "udp":
            # Any PTP from a non-OT-known source is suspicious
            if (self._ot_protected_ips
                    and saddr not in self._ot_protected_ips):
                alert_key = f"ptp_spoof:{saddr}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_PTP_SPOOFING,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description=(
                            f"Possible PTP grandmaster spoofing: {saddr} is "
                            f"sending IEEE 1588 (PTP) event messages but is "
                            f"not a known OT device. PTP spoofing desynchronises "
                            f"precision industrial clocks."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=saddr,
                        dstip=daddr,
                        uid=[uid],
                        timestamp=timestamp,
                        port=dport,
                        proto=Proto.UDP,
                    )

    # ── Modbus deep-packet events (from Zeek OT parser) ─────────────────────

    def _handle_modbus(self, raw: str):
        """
        Process per-PDU Modbus events published by zeek-scripts/ot_protocols.zeek.
        Expected fields:
          {profileid, twid, srcip, dstip, uid, ts, func_code, is_exception, value}
        """
        try:
            ev = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        profileid = ev.get("profileid", "")
        twid = ev.get("twid", "")
        srcip = ev.get("srcip", "")
        dstip = ev.get("dstip", "")
        uid = ev.get("uid", "")
        timestamp = ev.get("ts", "")
        func_code = int(ev.get("func_code", 0) or 0)
        is_exception = bool(ev.get("is_exception", False))

        if not srcip:
            return

        # Unauthorized write
        if func_code in MODBUS_WRITE_FUNCTION_CODES:
            if (self._modbus_authorized_masters
                    and srcip not in self._modbus_authorized_masters):
                alert_key = f"mb_write:{srcip}:{dstip}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    func_names = {
                        5: "Write Single Coil",
                        6: "Write Single Register",
                        15: "Write Multiple Coils",
                        16: "Write Multiple Registers",
                        22: "Mask Write Register",
                        23: "Read/Write Multiple Registers",
                    }
                    fname = func_names.get(func_code,
                                           f"Function {func_code}")
                    self._set_evidence(
                        ev_type=EvidenceType.OT_MODBUS_WRITE_COILS,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.95,
                        description=(
                            f"Unauthorized Modbus write from {srcip} to "
                            f"OT device {dstip}: function '{fname}' "
                            f"(code {func_code}) by non-authorized master."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=srcip,
                        dstip=dstip,
                        uid=[uid],
                        timestamp=timestamp,
                        port=MODBUS_PORT,
                        proto=Proto.TCP,
                    )

        # Illegal / malformed function
        if is_exception or func_code > 127:
            alert_key = f"mb_illegal:{srcip}:{dstip}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                self._set_evidence(
                    ev_type=EvidenceType.OT_MODBUS_ILLEGAL_FUNCTION,
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    description=(
                        f"Modbus illegal/malformed function from {srcip} "
                        f"to {dstip}: function code {func_code}, "
                        f"exception={is_exception}."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=timestamp,
                    port=MODBUS_PORT,
                    proto=Proto.TCP,
                )

    # ── S7Comm deep-packet events ────────────────────────────────────────────

    def _handle_s7comm(self, raw: str):
        """
        Process per-PDU S7Comm events from Zeek OT parser.
        Expected: {profileid, twid, srcip, dstip, uid, ts, function, rosctr}
        """
        try:
            ev = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        profileid = ev.get("profileid", "")
        twid = ev.get("twid", "")
        srcip = ev.get("srcip", "")
        dstip = ev.get("dstip", "")
        uid = ev.get("uid", "")
        timestamp = ev.get("ts", "")
        function = int(ev.get("function", 0) or 0)
        # rosctr 1 = job, 3 = ack_data
        rosctr = int(ev.get("rosctr", 0) or 0)

        if not srcip:
            return

        # PLC STOP command
        if function in S7_DANGEROUS_FUNCTIONS and rosctr == 1:
            alert_key = f"s7_stop:{srcip}:{dstip}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                func_desc = {
                    0x29: "PLC Stop",
                    0x28: "PLC Start",
                    0x00: "CPU services",
                }.get(function, f"0x{function:02X}")
                self._set_evidence(
                    ev_type=EvidenceType.OT_S7COMM_PLC_STOP,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.95,
                    description=(
                        f"Siemens S7Comm STOP/control-plane command from "
                        f"{srcip} to PLC {dstip}: function {func_desc} — "
                        f"this can halt industrial processes immediately."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=timestamp,
                    port=S7COMM_PORT,
                    proto=Proto.TCP,
                )

        # Unauthorized write (function 5 = WriteVar)
        # FIX: Use _s7_authorized_masters instead of _modbus_authorized_masters
        if function == 0x05 and rosctr == 1:
            if (self._s7_authorized_masters
                    and srcip not in self._s7_authorized_masters):
                alert_key = f"s7_write:{srcip}:{dstip}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_S7COMM_UNAUTHORIZED_WRITE,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description=(
                            f"Unauthorized S7Comm WriteVar from {srcip} to "
                            f"PLC {dstip} — variable write from non-authorised "
                            f"source."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=srcip,
                        dstip=dstip,
                        uid=[uid],
                        timestamp=timestamp,
                        port=S7COMM_PORT,
                        proto=Proto.TCP,
                    )

    # ── DNP3 deep-packet events ──────────────────────────────────────────────

    def _handle_dnp3(self, raw: str):
        """
        Process per-PDU DNP3 events from Zeek OT parser.
        Expected: {profileid, twid, srcip, dstip, uid, ts, function_code, is_unsolicited}
        """
        try:
            ev = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        profileid = ev.get("profileid", "")
        twid = ev.get("twid", "")
        srcip = ev.get("srcip", "")
        dstip = ev.get("dstip", "")
        uid = ev.get("uid", "")
        timestamp = ev.get("ts", "")
        function_code = int(ev.get("function_code", 0) or 0)

        if not srcip:
            return

        # DNP3 unauthorized function codes (> 33 are reserved/dangerous)
        if function_code > 33:
            alert_key = f"dnp3_func:{srcip}:{dstip}:{function_code}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                self._set_evidence(
                    ev_type=EvidenceType.OT_DNP3_UNAUTHORIZED_FUNCTION,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description=(
                        f"DNP3 unsupported/unauthorized function code "
                        f"{function_code} from {srcip} to {dstip}."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=timestamp,
                    port=DNP3_PORT,
                    proto=Proto.TCP,
                )

    # ── PLC mode-switch detection (via notice channel) ───────────────────────

    def _handle_notice(self, raw: str):
        """
        React to Zeek notice.log entries, especially custom OT notices
        published by ot_protocols.zeek.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return

        # new_notice wraps the notice fields in a nested "flow" dict, with
        # profileid/twid at the top level (see profile_handler.add_out_notice).
        profileid = data.get("profileid", "")
        twid = data.get("twid", "")
        flow: dict = data.get("flow", {})
        if not (profileid and isinstance(flow, dict)):
            return

        note = flow.get("note", "")
        srcip = flow.get("saddr", "")
        dstip = flow.get("daddr", "")
        uid = flow.get("uid", "")
        ts = flow.get("starttime", "")

        # OT Zeek scripts emit "OT::PLCModeSwitch" notices
        if "PLCModeSwitch" in note:
            now = time.time()
            self._plc_mode_switches[dstip].append(now)
            self._plc_mode_switches[dstip] = [
                t for t in self._plc_mode_switches[dstip]
                if now - t <= 60
            ]
            count = len(self._plc_mode_switches[dstip])

            if count >= self._plc_mode_switch_threshold:
                alert_key = f"plc_mode:{dstip}:{twid}"
                if alert_key not in self._alerted:
                    self._alerted.add(alert_key)
                    self._set_evidence(
                        ev_type=EvidenceType.OT_PLC_MODE_SWITCH,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.95,
                        description=(
                            f"PLC mode-switching attack: {srcip} sent "
                            f"{count} RUN/STOP mode-switch commands to PLC "
                            f"{dstip} within 60s — this can crash the PLC "
                            f"or trigger a fault state."
                        ),
                        profileid=profileid,
                        twid=twid,
                        srcip=srcip,
                        dstip=dstip,
                        uid=[uid],
                        timestamp=ts,
                        port=S7COMM_PORT,
                        proto=Proto.TCP,
                    )

        # Watchdog manipulation notice
        if "WatchdogDisabled" in note or "WatchdogManipulation" in note:
            alert_key = f"watchdog:{dstip}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                self._set_evidence(
                    ev_type=EvidenceType.OT_WATCHDOG_MANIPULATION,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description=(
                        f"Watchdog timer manipulation detected on PLC {dstip} "
                        f"from {srcip} — safety systems may be bypassed."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=ts,
                    port=S7COMM_PORT,
                    proto=Proto.TCP,
                )

        # Valve/motor cycling notices
        if "ValveCycling" in note:
            alert_key = f"valve:{dstip}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                self._set_evidence(
                    ev_type=EvidenceType.OT_VALVE_CYCLING,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description=(
                        f"Rapid valve cycling attack on {dstip} from {srcip} "
                        f"— repeated open/close commands cause mechanical wear."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=ts,
                    port=S7COMM_PORT,
                    proto=Proto.TCP,
                )

        if "MotorCycling" in note:
            alert_key = f"motor:{dstip}:{twid}"
            if alert_key not in self._alerted:
                self._alerted.add(alert_key)
                self._set_evidence(
                    ev_type=EvidenceType.OT_MOTOR_CYCLING,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description=(
                        f"Motor start/stop cycling attack on {dstip} from "
                        f"{srcip} — rapid cycling overheats motors."
                    ),
                    profileid=profileid,
                    twid=twid,
                    srcip=srcip,
                    dstip=dstip,
                    uid=[uid],
                    timestamp=ts,
                    port=S7COMM_PORT,
                    proto=Proto.TCP,
                )

    # ── Evidence generation helper ───────────────────────────────────────────

    def _set_evidence(
        self,
        ev_type: EvidenceType,
        threat_level: ThreatLevel,
        confidence: float,
        description: str,
        profileid: str,
        twid: str,
        srcip: str,
        dstip: str,
        uid: List[str],
        timestamp: str,
        port: int = None,
        proto: Proto = None,
    ):
        """
        Build an Evidence object and publish it to the evidence pipeline.

        OT-safe blocking enforcement:
        If the *attacker* srcip is itself a protected OT device (e.g. it could
        be ARP-spoofed), we still generate evidence but flag the evidence so
        that the blocking module will NOT block that IP.  The description
        includes a note for the analyst.
        """
        srcip_is_protected = srcip in self._ot_protected_ips
        if srcip_is_protected:
            description += (
                "  [OT-SAFE: attacker IP is a protected OT device — "
                "blocking suppressed, manual investigation required.]"
            )

        twid_int = int(twid.replace("timewindow", "")) if twid else 0

        attacker = Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=srcip,
            profile=ProfileID(ip=srcip),
        )
        victim = Victim(
            direction=Direction.DST,
            ioc_type=IoCType.IP,
            value=dstip,
        )

        # Format the timestamp properly
        if timestamp:
            formatted_ts = utils.convert_ts_format(timestamp, utils.alerts_format)
        else:
            formatted_ts = utils.convert_ts_format(time.time(), utils.alerts_format)

        evidence = Evidence(
            evidence_type=ev_type,
            description=description,
            attacker=attacker,
            threat_level=threat_level,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_int),
            uid=uid if isinstance(uid, list) else [uid],
            timestamp=formatted_ts,
            victim=victim,
            proto=proto if proto else Proto.TCP,
            dst_port=port,
            confidence=confidence,
        )

        self.db.set_evidence(evidence)

        # Suppress blocking for protected OT device IPs
        if srcip_is_protected:
            self.db.mark_as_ot_protected(srcip)
