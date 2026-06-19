import csv
import os
from datetime import datetime


TRAFFIC_STATS_FILE = "logs/traffic_stats.csv"
AI_LOG_FILE = "logs/ai_detection_log.csv"


class AIDetector:

    def __init__(self):
        self.traffic_stats_file = TRAFFIC_STATS_FILE
        self.ai_log_file = AI_LOG_FILE

    def classify_traffic(self, packets, bytes_count):
        """
        Simple rule-based detection logic.
        This will be improved later using a real ML model.
        """

        if packets < 20:
            return "normal", "allow"

        if packets < 100:
            return "suspicious", "monitor"

        return "malicious", "block"

    def ensure_ai_log_file(self):
        os.makedirs("logs", exist_ok=True)

        if not os.path.exists(self.ai_log_file):
            with open(self.ai_log_file, mode="w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "timestamp",
                    "flow",
                    "source_ip",
                    "destination_ip",
                    "packets",
                    "bytes",
                    "classification",
                    "recommended_action"
                ])

    def save_detection_result(
        self,
        flow,
        source_ip,
        destination_ip,
        packets,
        bytes_count,
        classification,
        recommended_action
    ):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(self.ai_log_file, mode="a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                flow,
                source_ip,
                destination_ip,
                packets,
                bytes_count,
                classification,
                recommended_action
            ])

    def analyze(self):
        if not os.path.exists(self.traffic_stats_file):
            print(f"[ERROR] Traffic stats file not found: {self.traffic_stats_file}")
            return

        self.ensure_ai_log_file()

        print("\n========== AI Detection Results ==========")

        with open(self.traffic_stats_file, mode="r") as file:
            reader = csv.DictReader(file)

            for row in reader:
                flow = row["flow"]
                source_ip = row["source_ip"]
                destination_ip = row["destination_ip"]
                packets = int(row["packets"])
                bytes_count = int(row["bytes"])

                classification, recommended_action = self.classify_traffic(
                    packets,
                    bytes_count
                )

                print(f"\nFlow: {flow}")
                print(f"Source IP: {source_ip}")
                print(f"Destination IP: {destination_ip}")
                print(f"Packets: {packets}")
                print(f"Bytes: {bytes_count}")
                print(f"Classification: {classification}")
                print(f"Recommended Action: {recommended_action}")

                self.save_detection_result(
                    flow,
                    source_ip,
                    destination_ip,
                    packets,
                    bytes_count,
                    classification,
                    recommended_action
                )

        print("\n==========================================")
        print(f"[SUCCESS] AI detection results saved to {self.ai_log_file}")


def main():
    detector = AIDetector()
    detector.analyze()


if __name__ == "__main__":
    main()
