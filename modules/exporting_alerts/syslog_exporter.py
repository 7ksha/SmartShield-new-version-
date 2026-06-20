"""
SmartShield Syslog / Webhook Exporter
======================================
Exports SmartShield alerts to:
  1. **Syslog** (UDP/TCP) — compatible with Splunk, IBM QRadar, Wazuh,
     Elastic SIEM, Graylog, and any RFC-5424 syslog receiver.
  2. **Webhook (HTTP POST)** — generic JSON webhook for custom integrations,
     Grafana alerting, PagerDuty, or any HTTP endpoint.

Configuration (smartshield.yaml)
---------------------------------
    exporting_alerts:
      export_to: [syslog, webhook]

      # Syslog settings
      syslog_server: 192.168.1.100
      syslog_port: 514
      syslog_protocol: udp          # udp or tcp
      syslog_facility: 16           # local0=16 … local7=23
      syslog_app_name: smartshield

      # Webhook settings
      webhook_url: http://siem-server:9000/api/alerts
      webhook_timeout: 5            # seconds
      webhook_auth_token: ""        # Optional Bearer token
"""

import json
import logging
import logging.handlers
import socket
import time
from typing import Optional

import requests

from smartshield_files.common.parsers.config_parser import ConfigParser


class SyslogExporter:
    """
    Exports SmartShield alerts to a remote syslog server using Python's
    logging.handlers.SysLogHandler (UDP/TCP, RFC 5424 compatible).
    """

    _FACILITY_MAP = {
        "local0": 16, "local1": 17, "local2": 18, "local3": 19,
        "local4": 20, "local5": 21, "local6": 22, "local7": 23,
        "daemon": 3, "user": 1, "auth": 4, "security": 4,
    }

    def __init__(self, logger, db):
        self.logger = logger
        self.db = db
        self._handler: Optional[logging.handlers.SysLogHandler] = None
        self._syslog_logger: Optional[logging.Logger] = None
        self._read_config()

    def _read_config(self):
        conf = ConfigParser()
        self._server = conf.read_configuration(
            "exporting_alerts", "syslog_server", "127.0.0.1")
        self._port = int(conf.read_configuration(
            "exporting_alerts", "syslog_port", "514"))
        self._protocol = conf.read_configuration(
            "exporting_alerts", "syslog_protocol", "udp").lower()
        self._app_name = conf.read_configuration(
            "exporting_alerts", "syslog_app_name", "smartshield")

        facility_raw = conf.read_configuration(
            "exporting_alerts", "syslog_facility", "local0")
        # Accept either an integer or a name like "local0"
        try:
            self._facility = int(facility_raw)
        except ValueError:
            self._facility = self._FACILITY_MAP.get(
                str(facility_raw).lower(), 16)

    def should_export(self) -> bool:
        conf = ConfigParser()
        targets = conf.read_configuration("exporting_alerts", "export_to", [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.strip("[]").split(",")]
        return "syslog" in [str(t).strip().lower() for t in targets]

    def _ensure_handler(self):
        """Lazy-initialise the syslog handler on first use."""
        if self._handler is not None:
            return

        socktype = (
            socket.SOCK_DGRAM
            if self._protocol == "udp"
            else socket.SOCK_STREAM
        )
        try:
            self._handler = logging.handlers.SysLogHandler(
                address=(self._server, self._port),
                facility=self._facility,
                socktype=socktype,
            )
            fmt = logging.Formatter(
                f"{self._app_name}: %(message)s"
            )
            self._handler.setFormatter(fmt)
            self._syslog_logger = logging.getLogger("smartshield.syslog")
            self._syslog_logger.setLevel(logging.INFO)
            self._syslog_logger.addHandler(self._handler)
            self._syslog_logger.propagate = False
        except Exception as e:
            self._handler = None
            print(f"[SyslogExporter] Failed to connect to syslog "
                  f"{self._server}:{self._port} — {e}")

    def send_alert(self, alert: dict):
        """
        Serialize a SmartShield alert dict and send it to syslog.
        The message format is CEF-inspired for easy SIEM parsing.
        """
        self._ensure_handler()
        if not self._syslog_logger:
            return

        try:
            # Build a structured syslog message
            threat = alert.get("threat_level", "unknown").upper()
            attacker = alert.get("attacker", {}).get("value", "unknown")
            evidence_type = alert.get("evidence_type", "unknown")
            description = alert.get("description", "")
            ts = alert.get("timestamp", "")
            confidence = alert.get("confidence", 0.0)

            msg = (
                f"SmartShield ALERT | "
                f"type={evidence_type} | "
                f"threat={threat} | "
                f"confidence={confidence:.2f} | "
                f"attacker={attacker} | "
                f"ts={ts} | "
                f"desc={description[:200]}"
            )

            self._syslog_logger.info(msg)
        except Exception as e:
            print(f"[SyslogExporter] Failed to send alert: {e}")

    def shutdown_gracefully(self):
        if self._handler:
            try:
                self._handler.close()
            except Exception:
                pass


class WebhookExporter:
    """
    Posts SmartShield alerts as JSON to a configurable HTTP endpoint.
    Compatible with: Grafana, PagerDuty, Splunk HEC, custom SIEMs.
    """

    def __init__(self, logger, db):
        self.logger = logger
        self.db = db
        self._read_config()

    def _read_config(self):
        conf = ConfigParser()
        self._url = conf.read_configuration(
            "exporting_alerts", "webhook_url", "")
        self._timeout = int(conf.read_configuration(
            "exporting_alerts", "webhook_timeout", "5"))
        self._token = conf.read_configuration(
            "exporting_alerts", "webhook_auth_token", "")

    def should_export(self) -> bool:
        conf = ConfigParser()
        targets = conf.read_configuration("exporting_alerts", "export_to", [])
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.strip("[]").split(",")]
        return "webhook" in [str(t).strip().lower() for t in targets]

    def send_alert(self, alert: dict):
        """POST the alert as JSON to the webhook URL."""
        if not self._url:
            return

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        payload = {
            "source": "smartshield",
            "version": "2.0",
            "timestamp": alert.get("timestamp", ""),
            "alert": alert,
        }

        try:
            resp = requests.post(
                self._url,
                data=json.dumps(payload),
                headers=headers,
                timeout=self._timeout,
            )
            if resp.status_code >= 400:
                print(
                    f"[WebhookExporter] HTTP {resp.status_code} from "
                    f"{self._url}: {resp.text[:200]}"
                )
        except requests.exceptions.ConnectionError:
            print(f"[WebhookExporter] Cannot connect to {self._url}")
        except requests.exceptions.Timeout:
            print(f"[WebhookExporter] Timeout posting to {self._url}")
        except Exception as e:
            print(f"[WebhookExporter] Unexpected error: {e}")

    def shutdown_gracefully(self):
        pass
