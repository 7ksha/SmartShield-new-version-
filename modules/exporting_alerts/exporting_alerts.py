 
 
import json

from modules.exporting_alerts.slack_exporter import SlackExporter
from modules.exporting_alerts.stix_exporter import StixExporter
from modules.exporting_alerts.syslog_exporter import SyslogExporter, WebhookExporter
from smartshield_files.common.smartshield_utils import utils
from smartshield_files.common.abstracts.imodule import IModule


class ExportingAlerts(IModule):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment
    variables to use this module
    """

    name = "Exporting Alerts"
    description = "Export alerts to slack or STIX format"

    def init(self):
        self.slack = SlackExporter(self.logger, self.db)
        self.stix = StixExporter(self.logger, self.db)
        self.syslog = SyslogExporter(self.logger, self.db)
        self.webhook = WebhookExporter(self.logger, self.db)
        self.c1 = self.db.subscribe("export_evidence")
        self.channels = {"export_evidence": self.c1}
        self.print("Subscribed to export_evidence channel.", 1, 0)

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        self.stix.shutdown_gracefully()
        self.syslog.shutdown_gracefully()
        self.webhook.shutdown_gracefully()

    def pre_main(self):
        utils.drop_root_privs_permanently()

        export_to_slack = self.slack.should_export()
        export_to_stix = self.stix.should_export()
        export_to_syslog = self.syslog.should_export()
        export_to_webhook = self.webhook.should_export()

        if not export_to_slack and not export_to_stix and not export_to_syslog and not export_to_webhook:
            self.print(
                "Exporting Alerts module disabled (no export targets configured).",
                0,
                2,
            )
            return 1

        if export_to_slack:
            self.slack.send_init_msg()

        if export_to_stix and self.stix.is_running_non_stop:
            # This thread is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            self.stix.start_exporting_thread()

    def remove_sensitive_info(self, evidence: dict) -> str:
        """
        removes the leaked location co-ords from the evidence
        description before exporting
        returns the description without sensitive info
        """
        if "NETWORK_GPS_LOCATION_LEAKED" not in evidence["evidence_type"]:
            return evidence["description"]

        description = evidence["description"]
        return description[: description.index("Leaked location")]

    def main(self):
        # a msg is sent here for each evidence that was part of an alert
        if msg := self.get_msg("export_evidence"):
            evidence = json.loads(msg["data"])
            self.print(
                f"[ExportingAlerts] Evidence {evidence.get('id')} "
                f"type={evidence.get('evidence_type')} received.",
                2,
                0,
            )
            description = self.remove_sensitive_info(evidence)
            if self.slack.should_export():
                srcip = evidence["profile"]["ip"]
                msg_to_send = f"Src IP {srcip} Detected {description}"
                self.slack.export(msg_to_send)

            if self.stix.should_export():
                added_to_stix: bool = self.stix.add_to_stix_file(evidence)
                if added_to_stix:
                    # now export to taxii
                    self.stix.export()
                else:
                    self.print("Problem in add_to_stix_file()", 0, 3)

            if self.syslog.should_export():
                self.syslog.send_alert(evidence)

            if self.webhook.should_export():
                self.webhook.send_alert(evidence)
