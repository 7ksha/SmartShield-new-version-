

import os
import sys
import yaml
import argparse
from typing import Dict, List, Optional


class ConfigParser:
    """
    Parses the SmartShield YAML configuration file.
    Provides typed access to all configuration parameters.
    """

    def __init__(self, config_file: str = "config/smartshield.yaml"):
        self.config_file = config_file
        self.config = self._load_config()
        self._args = None

    def _load_config(self) -> dict:
        """Load the YAML configuration file."""
        try:
            with open(self.config_file) as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}
        except Exception:
            return {}

    def get_args(self):
        """Parse and return command-line arguments."""
        if self._args is not None:
            return self._args

        parser = argparse.ArgumentParser(description="SmartShield Network IDS/IPS")
        parser.add_argument("-c", "--config", default=self.config_file,
                          help="Path to configuration file")
        parser.add_argument("-f", "--file", dest="input_file", default=None,
                          help="Input file (pcap, zeek logs, etc.)")
        parser.add_argument("-i", "--interface", default=None,
                          help="Network interface to listen on")
        parser.add_argument("-o", "--output", default="output/",
                          help="Output directory")
        parser.add_argument("-v", "--verbose", type=int, default=None,
                          help="Verbosity level")
        parser.add_argument("-d", "--debug", type=int, default=None,
                          help="Debug level")
        parser.add_argument("-w", "--webinterface", action="store_true",
                          help="Enable web interface")
        parser.add_argument("-D", "--daemon", action="store_true",
                          help="Run in daemon mode")
        parser.add_argument("-S", "--stopdaemon", action="store_true",
                          help="Stop daemon")
        parser.add_argument("-s", action="store_true", help="Save DB")
        parser.add_argument("-cc", action="store_true",
                          help="Clear blocking chain")
        parser.add_argument("-cb", action="store_true", help="Clear blocking")
        parser.add_argument("-k", action="store_true", help="Kill mode")
        parser.add_argument("--blocking", action="store_true",
                          help="Enable blocking")
        parser.add_argument("-ap", "--access_point", action="store_true",
                          help="Access point mode")
        parser.add_argument("-db", action="store_true", help="Use DB from disk")
        parser.add_argument("-g", "--growing", default=None,
                          help="Growing zeek directory")
        parser.add_argument("-e", type=int, default=0,
                          help="Evidence export format")
        parser.add_argument("--killall", action="store_true",
                          help="Kill all redis servers")
        parser.add_argument("--pcapfilter", default=None,
                          help="Packet filter for pcap")

        self._args = parser.parse_args()
        # Re-read config if -c was given
        if self._args.config != self.config_file:
            self.config_file = self._args.config
            self.config = self._load_config()
        return self._args

    # ── Parameters section ──────────────────────────────────────────────────

    def verbose(self) -> int:
        return self.config.get("parameters", {}).get("verbose", 1)

    def debug(self) -> int:
        return self.config.get("parameters", {}).get("debug", 0)

    def get_tw_width(self):
        return self.config.get("parameters", {}).get("time_window_width", 3600)

    def get_tw_width_as_float(self) -> float:
        tw = self.get_tw_width()
        if isinstance(tw, (int, float)):
            return float(tw)
        return 3600.0

    def delete_prev_db(self) -> bool:
        return self.config.get("parameters", {}).get("deletePrevdb", False)

    def client_ips(self) -> List[str]:
        return self.config.get("parameters", {}).get("client_ips", []) or []

    def store_zeek_files_in_the_output_dir(self) -> bool:
        return self.config.get("parameters", {}).get(
            "store_zeek_files_in_the_output_dir", True
        )

    def store_a_copy_of_zeek_files(self) -> bool:
        return self.config.get("parameters", {}).get(
            "store_a_copy_of_zeek_files", False
        )

    def store_zeek_files_copy(self) -> bool:
        return self.store_a_copy_of_zeek_files()

    def delete_zeek_files(self) -> bool:
        return self.config.get("parameters", {}).get("delete_zeek_files", False)

    def analysis_direction(self) -> str:
        return self.config.get("parameters", {}).get("analysis_direction", "out")

    def export_strato_letters(self) -> bool:
        return self.config.get("parameters", {}).get(
            "export_strato_letters", False
        )

    def pcapfilter(self) -> Optional[str]:
        return self.config.get("parameters", {}).get("pcapfilter")

    # ── Detection section ───────────────────────────────────────────────────

    def evidence_detection_threshold(self):
        return self.config.get("detection", {}).get(
            "evidence_detection_threshold", 0.25
        )

    # ── Modules section ─────────────────────────────────────────────────────

    def get_disabled_modules(self, input_type: str = None) -> List[str]:
        return self.config.get("modules", {}).get("disable", ["template"])

    def timeline_human_timestamp(self) -> bool:
        return self.config.get("modules", {}).get(
            "timeline_human_timestamp", True
        )

    # ── FlowMLDetection section ─────────────────────────────────────────────

    def get_ml_mode(self) -> str:
        return self.config.get("flowmldetection", {}).get("mode", "test")

    # ── VirusTotal section ──────────────────────────────────────────────────

    def vt_api_key_file(self) -> str:
        return self.config.get("virustotal", {}).get("api_key_file", "")

    def virustotal_update_period(self) -> int:
        return self.config.get("virustotal", {}).get(
            "virustotal_update_period", 259200
        )

    # ── ThreatIntelligence section ──────────────────────────────────────────

    def wait_for_TI_to_finish(self) -> bool:
        return self.config.get("threatintelligence", {}).get(
            "wait_for_TI_to_finish", False
        )

    def local_ti_data_path(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "local_threat_intelligence_files", "config/local_ti_files/"
        )

    def remote_ti_data_path(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "download_path_for_remote_threat_intelligence",
            "modules/threat_intelligence/remote_data_files/",
        )

    def ti_files(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "ti_files", "config/TI_feeds.csv"
        )

    def ja3_feeds(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "ja3_feeds", "config/JA3_feeds.csv"
        )

    def ssl_feeds(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "ssl_feeds", "config/SSL_feeds.csv"
        )

    def mac_db(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "mac_db", "https://maclookup.app/downloads/json-database/get-db"
        )

    def mac_db_update_period(self) -> int:
        return self.config.get("threatintelligence", {}).get(
            "mac_db_update", 1209600
        )

    def riskiq_update_period(self) -> int:
        return self.config.get("threatintelligence", {}).get(
            "riskiq_update_period", 604800
        )

    def RiskIQ_credentials_path(self) -> str:
        return self.config.get("threatintelligence", {}).get(
            "RiskIQ_credentials_path", "config/RiskIQ_credentials"
        )

    def TI_files_update_period(self) -> int:
        return self.config.get("threatintelligence", {}).get(
            "TI_files_update_period", 86400
        )

    # ── Whitelists section ──────────────────────────────────────────────────

    def enable_online_whitelist(self) -> bool:
        return self.config.get("whitelists", {}).get(
            "enable_online_whitelist", True
        )

    def enable_local_whitelist(self) -> bool:
        return self.config.get("whitelists", {}).get(
            "enable_local_whitelist", True
        )

    def local_whitelist_path(self) -> str:
        return self.config.get("whitelists", {}).get(
            "local_whitelist_path", "config/whitelist.conf"
        )

    def online_whitelist(self) -> str:
        return self.config.get("whitelists", {}).get(
            "online_whitelist",
            "https://tranco-list.eu/download/X5QNN/10000",
        )

    def online_whitelist_update_period(self) -> int:
        return self.config.get("whitelists", {}).get(
            "online_whitelist_update_period", 86400
        )

    # ── FlowAlerts section ──────────────────────────────────────────────────

    def long_connection_threshold(self) -> int:
        return self.config.get("flowalerts", {}).get(
            "long_connection_threshold", 1500
        )

    def ssh_succesful_detection_threshold(self) -> int:
        return self.config.get("flowalerts", {}).get(
            "ssh_succesful_detection_threshold", 4290
        )

    def data_exfiltration_threshold(self) -> int:
        return self.config.get("flowalerts", {}).get(
            "data_exfiltration_threshold", 500
        )

    def get_entropy_threshold(self) -> float:
        return self.config.get("flowalerts", {}).get("entropy_threshold", 5.0)

    def get_pastebin_download_threshold(self) -> int:
        return self.config.get("flowalerts", {}).get(
            "pastebin_download_threshold", 700
        )

    # ── ExportingAlerts section ─────────────────────────────────────────────

    def export_to(self) -> List[str]:
        return self.config.get("exporting_alerts", {}).get("export_to", [])

    def slack_channel_name(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "slack_channel_name", ""
        )

    def slack_token_filepath(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "slack_api_path", "config/slack_bot_token_secret"
        )

    def sensor_name(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "sensor_name", "sensor1"
        )

    def taxii_server(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "TAXII_server", "localhost"
        )

    def taxii_port(self) -> int:
        return self.config.get("exporting_alerts", {}).get("port", 1234)

    def use_https(self) -> bool:
        return self.config.get("exporting_alerts", {}).get("use_https", False)

    def discovery_path(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "discovery_path", "/taxii2/"
        )

    def collection_name(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "collection_name", "Alerts"
        )

    def push_delay(self) -> int:
        return self.config.get("exporting_alerts", {}).get("push_delay", 3600)

    def taxii_username(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "taxii_username", "admin"
        )

    def taxii_password(self) -> str:
        return self.config.get("exporting_alerts", {}).get(
            "taxii_password", "changeme"
        )

    # ── CESNET section ──────────────────────────────────────────────────────

    def cesnet_conf_file(self) -> str:
        return self.config.get("CESNET", {}).get(
            "configuration_file", "config/warden.conf"
        )

    def send_to_warden(self) -> bool:
        return self.config.get("CESNET", {}).get("send_alerts", False)

    def receive_from_warden(self) -> bool:
        return self.config.get("CESNET", {}).get("receive_alerts", False)

    # ── DisabledAlerts section ──────────────────────────────────────────────

    def disabled_detections(self) -> List[str]:
        return self.config.get("DisabledAlerts", {}).get(
            "disabled_detections", []
        ) or []

    # ── Docker section ──────────────────────────────────────────────────────

    def get_UID(self) -> int:
        return self.config.get("Docker", {}).get("UID", 0)

    def get_GID(self) -> int:
        return self.config.get("Docker", {}).get("GID", 0)

    # ── GlobalP2P section ───────────────────────────────────────────────────

    def use_local_p2p(self) -> bool:
        return self.config.get("local_p2p", {}).get("use_p2p", False)

    def is_bootstrapping_node(self) -> bool:
        return self.config.get("global_p2p", {}).get(
            "bootstrapping_node", False
        )

    def get_bootstrapping_modules(self) -> List[str]:
        return self.config.get("global_p2p", {}).get(
            "bootstrapping_modules", ["fidesModule", "irisModule"]
        )

    def get_iris_config_location(self) -> str:
        return self.config.get("global_p2p", {}).get(
            "iris_conf", "config/iris_config.yaml"
        )

    # ── Profiling section ───────────────────────────────────────────────────

    def get_cpu_profiler_enable(self) -> bool:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_enable", False
        )

    def get_cpu_profiler_mode(self) -> str:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_mode", "dev"
        )

    def get_cpu_profiler_multiprocess(self) -> bool:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_multiprocess", False
        )

    def get_cpu_profiler_dev_mode_entries(self) -> int:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_dev_mode_entries", 500000
        )

    def get_cpu_profiler_output_limit(self) -> int:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_output_limit", 20
        )

    def get_cpu_profiler_sampling_interval(self) -> int:
        return self.config.get("Profiling", {}).get(
            "cpu_profiler_sampling_interval", 20
        )

    def get_memory_profiler_enable(self) -> bool:
        return self.config.get("Profiling", {}).get(
            "memory_profiler_enable", False
        )

    def get_memory_profiler_mode(self) -> str:
        return self.config.get("Profiling", {}).get(
            "memory_profiler_mode", "live"
        )

    def get_memory_profiler_multiprocess(self) -> bool:
        return self.config.get("Profiling", {}).get(
            "memory_profiler_multiprocess", True
        )

    # ── WebInterface section ────────────────────────────────────────────────

    def web_interface_port(self) -> int:
        return self.config.get("web_interface", {}).get("port", 55000)

    # ── wait_for_modules_to_finish ──────────────────────────────────────────

    def wait_for_modules_to_finish(self) -> float:
        val = self.config.get("parameters", {}).get(
            "wait_for_modules_to_finish", 10080
        )
        # Value may be like "10080 mins" - extract number
        if isinstance(val, str):
            import re
            m = re.search(r"(\d+)", val)
            if m:
                return float(m.group(1))
            return 10080.0
        return float(val)

    # ── General helpers ─────────────────────────────────────────────────────

    def read_configuration(self, section: str, key: str, default=""):
        """Read a generic configuration value."""
        return self.config.get(section, {}).get(key, default)

    def export_labeled_flows(self) -> bool:
        return self.config.get("parameters", {}).get(
            "export_labeled_flows", False
        )

    def export_labeled_flows_to(self) -> str:
        return self.config.get("parameters", {}).get("export_format", "json")

    def enable_metadata(self) -> bool:
        return self.config.get("parameters", {}).get("metadata_dir", True)
