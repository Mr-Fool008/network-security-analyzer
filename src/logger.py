import csv
import json
import os
import time
from pathlib import Path

class SecurityLogger:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.json_log_path = self.output_dir / "alerts.json"
        self.csv_log_path = self.output_dir / "traffic_summary.csv"

    def log_alerts_json(self, alerts: list):
        """Appends security alerts to a JSON-Lines log file."""
        if not alerts:
            return

        with open(self.json_log_path, "a", encoding="utf-8") as f:
            for alert in alerts:
                entry = {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "epoch_time": time.time(),
                    "alert_type": alert.get("type"),
                    "target_host": alert.get("source_ip") or alert.get("target_ip"),
                    "details": alert.get("details", "")
                }
                f.write(json.dumps(entry) + "\n")
        print(f"[+] Exported {len(alerts)} alerts to {self.json_log_path}")

    def log_traffic_summary_csv(self, protocol_counts: dict, top_talkers: list):
        """Exports protocol metrics and top talkers to CSV."""
        with open(self.csv_log_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            
            # Write Protocol Summary Section
            writer.writerow(["--- Protocol Distribution ---"])
            writer.writerow(["Protocol", "Packet Count"])
            for proto, count in protocol_counts.items():
                writer.writerow([proto, count])
            writer.writerow([])

            # Write Top Talkers Section
            writer.writerow(["--- Top-K Active Talkers ---"])
            writer.writerow(["Rank", "IP Address", "Packet Count"])
            for rank, (count, ip) in enumerate(top_talkers, start=1):
                writer.writerow([rank, ip, count])

        print(f"[+] Exported traffic summary to {self.csv_log_path}")