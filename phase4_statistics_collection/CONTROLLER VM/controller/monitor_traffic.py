import sys
import csv
import os
from datetime import datetime

sys.path.append("/home/p4/tutorials/utils")

from switch_manager import SwitchManager
from logger import Logger
from config import ATTACKER_IP, BANK_SERVER_IP


LOG_DIR = "logs"
CSV_FILE = os.path.join(LOG_DIR, "traffic_stats.csv")


def read_counter(manager, counter_name, index):
    counter_id = manager.helper.get_counters_id(counter_name)

    for response in manager.switch.ReadCounters(counter_id, index):
        for entity in response.entities:
            counter_entry = entity.counter_entry
            data = counter_entry.data

            return data.packet_count, data.byte_count

    return 0, 0


def ensure_csv_file():
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "flow",
                "source_ip",
                "destination_ip",
                "packets",
                "bytes"
            ])


def write_stats_to_csv(flow, source_ip, destination_ip, packets, bytes_count):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(CSV_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            flow,
            source_ip,
            destination_ip,
            packets,
            bytes_count
        ])


def main():
    manager = SwitchManager()

    manager.connect_runtime_only()

    Logger.info("Reading traffic counters...")

    packets_1, bytes_1 = read_counter(
        manager,
        "MyIngress.traffic_counter",
        0
    )

    packets_2, bytes_2 = read_counter(
        manager,
        "MyIngress.traffic_counter",
        1
    )

    ensure_csv_file()

    write_stats_to_csv(
        "attacker_to_bank",
        ATTACKER_IP,
        BANK_SERVER_IP,
        packets_1,
        bytes_1
    )

    write_stats_to_csv(
        "bank_to_attacker",
        BANK_SERVER_IP,
        ATTACKER_IP,
        packets_2,
        bytes_2
    )

    print("\n========== Traffic Statistics ==========")

    print("\nFlow 1: Attacker -> Bank Server")
    print(f"Source: {ATTACKER_IP}")
    print(f"Destination: {BANK_SERVER_IP}")
    print(f"Packets: {packets_1}")
    print(f"Bytes: {bytes_1}")

    print("\nFlow 2: Bank Server -> Attacker")
    print(f"Source: {BANK_SERVER_IP}")
    print(f"Destination: {ATTACKER_IP}")
    print(f"Packets: {packets_2}")
    print(f"Bytes: {bytes_2}")

    print("\n========================================")

    Logger.success(f"Traffic statistics saved to {CSV_FILE}")


if __name__ == "__main__":
    main()
