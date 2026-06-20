
"""Flow classifier - converts dict flows to flow objects."""
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Flow:
    """Represents a network flow."""
    starttime: str = ""
    uid: str = ""
    saddr: str = ""
    daddr: str = ""
    sport: int = 0
    dport: int = 0
    proto: str = ""
    state: str = ""
    dur: float = 0.0
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0
    pkts: int = 0
    bytes: int = 0
    note: str = ""
    msg: str = ""
    dns_query: str = ""
    dns_answer: str = ""
    tls_version: str = ""
    ja3: str = ""
    ja3s: str = ""
    ssh_version: str = ""
    ssh_success: bool = False
    http_uri: str = ""
    http_method: str = ""
    http_user_agent: str = ""
    http_host: str = ""
    http_status_code: str = ""
    http_status_msg: str = ""
    ssl_subject: str = ""
    ssl_issuer: str = ""
    ssl_fingerprint: str = ""
    tls_cipher_suite: str = ""
    tls_certificate_validity: str = ""
    tls_certificate_path: str = ""
    tls_certificate_issuer: str = ""
    tls_certificate_subject: str = ""
    tls_certificate_serial_number: str = ""
    tls_certificate_fingerprint: str = ""
    tls_certificate_version: str = ""
    tls_certificate_not_before: str = ""
    tls_certificate_not_after: str = ""
    tls_certificate_signature_algorithm: str = ""
    tls_certificate_key_algorithm: str = ""
    tls_certificate_key_size: str = ""
    tls_certificate_exponent: str = ""
    tls_certificate_curve: str = ""
    server_name: str = ""
    service: str = ""
    interface: str = ""
    profileid: str = ""
    twid: str = ""
    label: str = ""
    confidence: float = 0.0
    severity: str = ""
    tags: str = ""
    type_: str = ""
    category: str = ""
    source: str = ""
    description: str = ""
    action: str = ""
    feedback: str = ""
    requested_addr: str = ""
    uids: list = field(default_factory=list)
    flow: dict = field(default_factory=dict)
    smac: str = ""
    dmac: str = ""
    vendor: str = ""
    model: str = ""
    os: str = ""
    version: str = ""
    type: str = ""
    hostname: str = ""
    device_type: str = ""
    device_vendor: str = ""
    device_model: str = ""
    device_os: str = ""
    device_version: str = ""
    device_hostname: str = ""
    device_type_id: str = ""
    device_vendor_id: str = ""
    device_model_id: str = ""
    device_os_id: str = ""
    device_version_id: str = ""
    device_hostname_id: str = ""
    smac_vendor: str = ""
    dmac_vendor: str = ""
    id_orig_h: str = ""
    id_orig_p: int = 0
    id_resp_h: str = ""
    id_resp_p: int = 0


class FlowClassifier:
    """Classifies and converts flows from dict to Flow objects."""

    def convert_to_flow_obj(self, flow_dict: dict) -> Flow:
        """Convert a dictionary to a Flow dataclass object."""
        if not isinstance(flow_dict, dict):
            flow_dict = {}
        flow = Flow()
        for key, value in flow_dict.items():
            if hasattr(flow, key):
                setattr(flow, key, value)
            # Handle common aliases
            elif key == "ts" and not flow.starttime:
                flow.starttime = str(value)
            elif key == "id.orig_h":
                flow.id_orig_h = value
                if not flow.saddr:
                    flow.saddr = value
            elif key == "id.orig_p":
                flow.id_orig_p = int(value) if value else 0
                if not flow.sport:
                    flow.sport = int(value) if value else 0
            elif key == "id.resp_h":
                flow.id_resp_h = value
                if not flow.daddr:
                    flow.daddr = value
            elif key == "id.resp_p":
                flow.id_resp_p = int(value) if value else 0
                if not flow.dport:
                    flow.dport = int(value) if value else 0
        return flow

    def classify(self, flow: Flow) -> str:
        """Classify a flow type based on its attributes."""
        if flow.dns_query:
            return "dns"
        if flow.tls_version or flow.ja3:
            return "ssl"
        if flow.ssh_version:
            return "ssh"
        if flow.http_method:
            return "http"
        return "conn"
