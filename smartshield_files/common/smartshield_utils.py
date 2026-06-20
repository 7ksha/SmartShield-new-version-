

"""
Common utility functions used across SmartShield.
"""

import hashlib
import ipaddress
import json
import os
import platform
import re
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Union


class Utils:
    """Centralized utility class for SmartShield."""

    # Time format used in alerts
    alerts_format = "%Y/%m/%d %H:%M:%S.%f%z"
    # Default log format
    log_format = "%Y/%m/%d %H:%M:%S.%f%z"

    # Directory for SmartShield lock files
    smartshield_locks_dir = "/tmp/smartshield/"

    # Threat level mappings
    threat_levels = {
        "info": 0,
        "low": 0.2,
        "medium": 0.5,
        "high": 0.8,
        "critical": 1,
    }

    def __init__(self):
        pass

    @staticmethod
    def get_smartshield_version() -> str:
        """Read the version from the VERSION file."""
        try:
            with open("VERSION") as f:
                return f.read().strip()
        except FileNotFoundError:
            return "unknown"

    @staticmethod
    def drop_root_privs_permanently():
        """Drop root privileges if running as root."""
        if os.getuid() == 0:
            try:
                import pwd
                nobody = pwd.getpwnam("nobody")
                os.setgid(nobody.pw_gid)
                os.setuid(nobody.pw_uid)
            except Exception:
                pass

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if the given IP is a private IP."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def is_public_ip(ip: str) -> bool:
        """Check if the given IP is a public IP."""
        try:
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback
                        or addr.is_reserved or addr.is_multicast)
        except ValueError:
            return False

    @staticmethod
    def is_ignored_ip(ip: str) -> bool:
        """Check if the IP should be ignored (localhost, multicast, etc.)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_multicast or addr.is_reserved or addr.is_loopback
        except ValueError:
            return True

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate that the given string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_own_ips(ret: str = "list"):
        """Get the IPs of the local machine."""
        ips = []
        try:
            import socket
            hostname = socket.gethostname()
            ips = socket.getaddrinfo(hostname, None)
            ips = list(set([ip[4][0] for ip in ips]))
        except Exception:
            pass
        if ret.lower() == "list":
            return ips
        return ips

    @staticmethod
    def is_port_in_use(port: int) -> bool:
        """Check if a port is in use."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(("localhost", port)) == 0

    @staticmethod
    def get_md5_hash(string: str) -> str:
        """Get MD5 hash of a string."""
        return hashlib.md5(string.encode()).hexdigest()

    @staticmethod
    def get_sha256_hash_of_file_contents(filepath: str) -> str:
        """Get SHA256 hash of a file's contents."""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except FileNotFoundError:
            return ""

    @staticmethod
    def get_time_format(timestamp: str) -> str:
        """Determine the time format of a timestamp string."""
        try:
            datetime.strptime(timestamp, Utils.alerts_format)
            return Utils.alerts_format
        except (ValueError, TypeError):
            pass
        # Try ISO format
        try:
            datetime.fromisoformat(timestamp)
            return "iso"
        except (ValueError, TypeError):
            pass
        return "unknown"

    @staticmethod
    def is_iso_format(timestamp: str) -> bool:
        """Check if the timestamp is in ISO format."""
        try:
            datetime.fromisoformat(timestamp)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def convert_ts_format(timestamp, format: str):
        """Convert a timestamp to the specified format."""
        if timestamp is None:
            timestamp = time.time()

        if isinstance(timestamp, (int, float)):
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        elif isinstance(timestamp, str):
            # Try parsing
            try:
                dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
            except ValueError:
                try:
                    dt = datetime.fromisoformat(timestamp)
                except ValueError:
                    dt = datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S.%f%z")
        elif isinstance(timestamp, datetime):
            dt = timestamp
        else:
            dt = datetime.now(timezone.utc)

        if format == "unixtimestamp":
            return str(dt.timestamp())
        elif format == Utils.alerts_format:
            return dt.strftime(Utils.alerts_format)
        else:
            return dt.strftime(format)

    @staticmethod
    def get_human_readable_datetime(format: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Get current time as a human-readable string."""
        return datetime.now().strftime(format)

    @staticmethod
    def get_time_diff(start, end, return_type: str = "seconds"):
        """Get time difference between two timestamps."""
        if isinstance(start, str):
            try:
                start = float(start)
            except ValueError:
                start = datetime.fromisoformat(start).timestamp()
        if isinstance(end, str):
            try:
                end = float(end)
            except ValueError:
                end = datetime.fromisoformat(end).timestamp()
        if isinstance(start, datetime):
            start = start.timestamp()
        if isinstance(end, datetime):
            end = end.timestamp()

        diff = abs(float(end) - float(start))
        if return_type == "minutes":
            return diff / 60
        return diff

    @staticmethod
    def is_ignored_zeek_log_file(filename: str) -> bool:
        """Check if a Zeek log file should be ignored."""
        ignored = {
            "LoadedScripts", "packet_filter", "capture_loss",
            "stats", "irc", "dpd", "reporter",
        }
        base = filename.replace(".log", "").replace(".labeled", "")
        return base in ignored

    @staticmethod
    def is_msg_intended_for(message: dict, channel: str) -> bool:
        """Check if a Redis message is intended for the given channel."""
        if not message or message.get("type") != "message":
            return False
        return message.get("channel") == channel

    @staticmethod
    def to_dict(obj):
        """Convert a dataclass object to a dictionary recursively."""
        if hasattr(obj, "__dataclass_fields__"):
            result = {}
            for key, value in obj.__dict__.items():
                # Skip private fields
                if key.startswith("_"):
                    continue
                result[key] = Utils.to_dict(value)
            return result
        elif isinstance(obj, (list, tuple)):
            return [Utils.to_dict(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: Utils.to_dict(v) for k, v in obj.items()}
        elif hasattr(obj, "value") and hasattr(obj, "name"):
            # Enum
            return obj.value if isinstance(obj.value, (str, int, float, bool)) else obj.name
        else:
            return obj

    @staticmethod
    def to_json_serializable(obj):
        """Convert an object to a JSON-serializable form."""
        return Utils.to_dict(obj)

    @staticmethod
    def calculate_confidence(pkts_sent: int, threshold: int = 10) -> float:
        """Calculate confidence based on packets sent."""
        if pkts_sent >= threshold * 2:
            return 1.0
        return min(pkts_sent / threshold, 1.0)

    @staticmethod
    def get_sudo_according_to_env() -> str:
        """Return 'sudo ' if not in Docker, empty string if in Docker."""
        if os.environ.get("IS_IN_A_DOCKER_CONTAINER", False):
            return ""
        return "sudo "

    @staticmethod
    def get_all_interfaces(args) -> List[str]:
        """Get all network interfaces."""
        interfaces = []
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
        except ImportError:
            try:
                result = subprocess.run(["ip", "-o", "link", "show"],
                                      capture_output=True, text=True)
                for line in result.stdout.split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        iface = parts[1].strip()
                        if iface:
                            interfaces.append(iface)
            except Exception:
                pass
        return interfaces

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if a string looks like a valid domain name."""
        if not domain or len(domain) > 253:
            return False
        pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
            r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
        )
        return bool(pattern.match(domain))

    @staticmethod
    def is_valid_threat_level(threat_level: str) -> bool:
        """Check if the given string is a valid threat level name."""
        return threat_level.lower() in Utils.threat_levels

    @staticmethod
    def threat_level_to_string(threat_level: float) -> str:
        """Convert a numeric threat level to its string name."""
        for name, value in Utils.threat_levels.items():
            if value == threat_level:
                return name
        return "unknown"

    @staticmethod
    def get_branch_info():
        """Get git branch and commit info."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, cwd=os.getcwd(),
            )
            branch = result.stdout.strip()
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, cwd=os.getcwd(),
            )
            commit = result.stdout.strip()
            return commit, branch
        except Exception:
            return False

    @staticmethod
    def detect_ioc_type(ioc: str) -> str:
        """Detect whether an IoC is an IP, domain, or URL."""
        if Utils.validate_ip_address(ioc):
            return "ip"
        if ioc.startswith("http://") or ioc.startswith("https://"):
            return "url"
        if Utils.is_valid_domain(ioc):
            return "domain"
        return "unknown"

    @staticmethod
    def sanitize(string: str) -> str:
        """Sanitize a string for safe logging/display."""
        return re.sub(r"[^\w\s\-\.:;/@=]", "", string)[:500]

    @staticmethod
    def assert_microseconds(timestamp: str) -> str:
        """Ensure timestamp has microseconds."""
        if "." not in timestamp:
            timestamp += ".000000"
        return timestamp

    @staticmethod
    def remove_milliseconds_decimals(timestamp: str) -> str:
        """Remove extra decimal places from milliseconds in timestamp."""
        parts = timestamp.split(".")
        if len(parts) == 2:
            ms_part = parts[1]
            # Keep only up to 6 digits for microseconds
            if len(ms_part) > 6:
                parts[1] = ms_part[:6]
            timestamp = ".".join(parts)
        return timestamp

    @staticmethod
    def convert_to_mb(size_bytes: int) -> float:
        """Convert bytes to megabytes."""
        return size_bytes / (1024 * 1024)

    @staticmethod
    def convert_to_datetime(timestamp) -> Optional[datetime]:
        """Convert various timestamp formats to datetime."""
        if isinstance(timestamp, datetime):
            return timestamp
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        if isinstance(timestamp, str):
            try:
                return datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
            except ValueError:
                pass
            try:
                return datetime.fromisoformat(timestamp)
            except ValueError:
                pass
            try:
                return datetime.strptime(timestamp, Utils.alerts_format)
            except ValueError:
                pass
        return None

    @staticmethod
    def is_datetime_obj(obj) -> bool:
        """Check if obj is a datetime instance."""
        return isinstance(obj, datetime)

    @staticmethod
    def is_aware(dt: datetime) -> bool:
        """Check if a datetime is timezone-aware."""
        return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None

    @staticmethod
    def to_delta(time_str: str) -> timedelta:
        """Convert a time string like '1day', '2hr', '30min' to timedelta."""
        match = re.match(r"(\\d+)\\s*(day|hr|hour|min|sec)s?", time_str, re.I)
        if not match:
            return timedelta()
        num = int(match.group(1))
        unit = match.group(2).lower()
        if unit.startswith("day"):
            return timedelta(days=num)
        elif unit.startswith("hr") or unit.startswith("hour"):
            return timedelta(hours=num)
        elif unit.startswith("min"):
            return timedelta(minutes=num)
        elif unit.startswith("sec"):
            return timedelta(seconds=num)
        return timedelta()

    @staticmethod
    def get_cidr_of_private_ip(ip: str) -> str:
        """Get the CIDR of a private IP's subnet."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                # Find which private range it belongs to
                for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
                    if addr in ipaddress.ip_network(network):
                        return network
            return ""
        except ValueError:
            return ""

    @staticmethod
    def get_first_octet(ip: str) -> str:
        """Get the first octet of an IPv4 address."""
        try:
            return str(ipaddress.ip_address(ip).packed[0])
        except ValueError:
            return ""

    @staticmethod
    def is_valid_uuid4(uuid_str: str) -> bool:
        """Check if a string is a valid UUID4."""
        import uuid
        try:
            uuid.UUID(uuid_str, version=4)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def start_thread(target, args=(), daemon=True):
        """Start a daemon thread."""
        import threading
        t = threading.Thread(target=target, args=args, daemon=daemon)
        t.start()
        return t

    @staticmethod
    def ip_to_list(ip: str) -> List[int]:
        """Convert an IPv4 address to a list of octets."""
        try:
            return [int(o) for o in ip.split(".")]
        except ValueError:
            return []

    @staticmethod
    def get_aid():
        """Generate an Analysis ID (AID)."""
        import uuid
        return str(uuid.uuid4())


# Global instance for convenient importing
utils = Utils()
