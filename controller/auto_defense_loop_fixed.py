import time
import csv
import os
from datetime import datetime

from switch_manager import SwitchManager
from defense_manager import DefenseManager
from logger import Logger
from config import ATTACKER_IP, BANK_SERVER_IP
from advanced_ai_detector import AdvancedAIDetector


CHECK_INTERVAL_SECONDS = 3

TRAFFIC_STATS_FILE = "logs/traffic_stats.csv"
AI_LOG_FILE = "logs/ai_detection_log.csv"
HONEYPOT_IP = "10.0.2.2"

VIRTUAL_BANK_IPS = [
    "10.0.1.100",
    "10.0.1.101",
    "10.0.1.102"
]

STATE_FILE = "current_active_ip.txt"
SHUFFLE_LOG_FILE = "logs/ip_shuffle_log.csv"

BANK_SERVER_MAC = "08:00:27:28:e4:91"
SWITCH_ETH2_MAC = "08:00:27:46:ec:8a"

HONEYPOT_MAC = "08:00:27:72:ea:d0"
SWITCH_ETH3_MAC = "08:00:27:3c:7f:0e"

PORT_TO_BANK = 2
PORT_TO_HONEYPOT = 3


def ensure_logs():
    os.makedirs("logs", exist_ok=True)

    if not os.path.exists(TRAFFIC_STATS_FILE):
        with open(TRAFFIC_STATS_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "flow",
                "source_ip",
                "destination_ip",
                "packets",
                "bytes"
            ])

    if not os.path.exists(AI_LOG_FILE):
        with open(AI_LOG_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "flow",
                "source_ip",
                "destination_ip",
                "packets",
                "bytes",
                "delta_packets",
                "delta_bytes",
                "packet_rate",
                "byte_rate",
                "avg_packet_size",
                "risk_score",
                "classification",
                "recommended_action",
                "reason"
            ])

    if not os.path.exists(SHUFFLE_LOG_FILE):
        with open(SHUFFLE_LOG_FILE, mode="w") as file:
            file.write("timestamp,active_ip,trap_ips\n")


def read_counter(manager, counter_name, index):
    counter_id = manager.helper.get_counters_id(counter_name)

    for response in manager.switch.ReadCounters(counter_id, index):
        for entity in response.entities:
            data = entity.counter_entry.data
            return data.packet_count, data.byte_count

    return 0, 0


def save_traffic_stats(flow, source_ip, destination_ip, packets, bytes_count):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(TRAFFIC_STATS_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            flow,
            source_ip,
            destination_ip,
            packets,
            bytes_count
        ])


def save_ai_result(flow, source_ip, destination_ip, packets, bytes_count, ai_result):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(AI_LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            flow,
            source_ip,
            destination_ip,
            packets,
            bytes_count,
            ai_result["delta_packets"],
            ai_result["delta_bytes"],
            ai_result["packet_rate"],
            ai_result["byte_rate"],
            ai_result["avg_packet_size"],
            ai_result["risk_score"],
            ai_result["classification"],
            ai_result["recommended_action"],
            ai_result["reason"]
        ])


def print_flow_result(flow, source_ip, destination_ip, packets, bytes_count, ai_result):
    print("\n========== Advanced AI Defense Check ==========")
    print(f"Flow: {flow}")
    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Total Packets: {packets}")
    print(f"Total Bytes: {bytes_count}")
    print(f"Delta Packets: {ai_result['delta_packets']}")
    print(f"Delta Bytes: {ai_result['delta_bytes']}")
    print(f"Packet Rate: {ai_result['packet_rate']} packets/sec")
    print(f"Byte Rate: {ai_result['byte_rate']} bytes/sec")
    print(f"Average Packet Size: {ai_result['avg_packet_size']} bytes")
    print(f"Risk Score: {ai_result['risk_score']}/100")
    print(f"Classification: {ai_result['classification']}")
    print(f"Recommended Action: {ai_result['recommended_action']}")
    print(f"Reason: {ai_result['reason']}")
    print("================================================")


def print_honeypot_counter(packets, bytes_count):
    print("\n========== Honeypot Redirect Counter ==========")
    print("Flow: attacker_to_honeypot")
    print(f"Source IP: {ATTACKER_IP}")
    print(f"Destination IP: {HONEYPOT_IP}")
    print(f"Honeypot Packets: {packets}")
    print(f"Honeypot Bytes: {bytes_count}")
    print("===============================================")


def read_current_active_ip():
    if not os.path.exists(STATE_FILE):
        return None

    with open(STATE_FILE, "r") as file:
        value = file.read().strip()

    if value in VIRTUAL_BANK_IPS:
        return value

    return None


def get_next_active_ip():
    current_ip = read_current_active_ip()

    if current_ip is None:
        return VIRTUAL_BANK_IPS[0]

    current_index = VIRTUAL_BANK_IPS.index(current_ip)
    next_index = (current_index + 1) % len(VIRTUAL_BANK_IPS)

    return VIRTUAL_BANK_IPS[next_index]


def save_current_active_ip(active_ip):
    with open(STATE_FILE, "w") as file:
        file.write(active_ip + "\n")


def log_shuffle(active_ip, trap_ips):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    trap_ips_text = "|".join(trap_ips)

    with open(SHUFFLE_LOG_FILE, "a") as file:
        file.write(f"{timestamp},{active_ip},{trap_ips_text}\n")


def install_lpm_route(
    switch_manager,
    dst_ip,
    prefix_len,
    port,
    dst_mac,
    src_mac,
    counter_index
):
    table_entry = switch_manager.helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip, prefix_len)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "port": port,
            "dstMac": dst_mac,
            "srcMac": src_mac,
            "counterIndex": counter_index
        }
    )

    switch_manager.switch.WriteTableEntry(table_entry)


def apply_ip_shuffle_same_connection(switch_manager):
    active_ip = get_next_active_ip()

    trap_ips = [
        ip for ip in VIRTUAL_BANK_IPS
        if ip != active_ip
    ]

    Logger.defense("Applying IP Shuffling using same switch connection...")
    Logger.info(f"New active bank IP: {active_ip}")

    for virtual_ip in VIRTUAL_BANK_IPS:
        if virtual_ip == active_ip:
            install_lpm_route(
                switch_manager=switch_manager,
                dst_ip=virtual_ip,
                prefix_len=32,
                port=PORT_TO_BANK,
                dst_mac=BANK_SERVER_MAC,
                src_mac=SWITCH_ETH2_MAC,
                counter_index=0
            )

            Logger.success(f"ACTIVE: {virtual_ip} -> Bank Server")

        else:
            install_lpm_route(
                switch_manager=switch_manager,
                dst_ip=virtual_ip,
                prefix_len=32,
                port=PORT_TO_HONEYPOT,
                dst_mac=HONEYPOT_MAC,
                src_mac=SWITCH_ETH3_MAC,
                counter_index=2
            )

            Logger.defense(f"TRAP: {virtual_ip} -> Honeypot")

    save_current_active_ip(active_ip)
    log_shuffle(active_ip, trap_ips)

    print("\n========== IP Shuffling Applied ==========")
    print(f"Active Bank IP : {active_ip} -> Bank Server")
    print("Trap IPs:")
    for trap_ip in trap_ips:
        print(f"  - {trap_ip} -> Honeypot")
    print("==========================================")


def main():
    Logger.info("Starting FIXED Advanced Auto Defense Loop...")

    ensure_logs()

    switch_manager = SwitchManager()
    switch_manager.connect()
    switch_manager.install_forwarding_rules()

    defense_manager = DefenseManager(switch_manager)
    ai_detector = AdvancedAIDetector()

    redirected = False
    ip_shuffle_triggered = False

    Logger.success("Initial pipeline and forwarding rules installed")
    Logger.info("Fixed advanced auto defense loop is running")

    while True:
        packets_1, bytes_1 = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            0
        )

        packets_2, bytes_2 = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            1
        )

        packets_3, bytes_3 = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            2
        )

        save_traffic_stats(
            "attacker_to_bank",
            ATTACKER_IP,
            BANK_SERVER_IP,
            packets_1,
            bytes_1
        )

        save_traffic_stats(
            "bank_to_attacker",
            BANK_SERVER_IP,
            ATTACKER_IP,
            packets_2,
            bytes_2
        )

        save_traffic_stats(
            "attacker_to_honeypot",
            ATTACKER_IP,
            HONEYPOT_IP,
            packets_3,
            bytes_3
        )

        ai_result = ai_detector.analyze(
            current_packets=packets_1,
            current_bytes=bytes_1
        )

        save_ai_result(
            "attacker_to_bank",
            ATTACKER_IP,
            BANK_SERVER_IP,
            packets_1,
            bytes_1,
            ai_result
        )

        print_flow_result(
            "attacker_to_bank",
            ATTACKER_IP,
            BANK_SERVER_IP,
            packets_1,
            bytes_1,
            ai_result
        )

        print_honeypot_counter(packets_3, bytes_3)

        action = ai_result["recommended_action"]

        if action == "redirect" and not redirected:
            Logger.defense("Advanced AI detected malicious traffic.")

            if not ip_shuffle_triggered:
                apply_ip_shuffle_same_connection(switch_manager)
                ip_shuffle_triggered = True

            Logger.defense("Installing redirect rule LAST...")
            defense_manager.redirect_attacker_to_honeypot()
            redirected = True

            Logger.success("Attacker traffic is now redirected to Honeypot")

        elif action == "redirect" and redirected:
            Logger.warning("Attacker is already redirected to Honeypot")

        elif action == "monitor":
            if redirected:
                Logger.warning(
                    "Bank path shows suspicious activity while attacker is already in Honeypot."
                )
            else:
                Logger.warning("Suspicious traffic detected. Monitoring attacker...")

        elif action == "allow":
            if redirected:
                Logger.success("Bank path is clean. Attacker remains redirected to Honeypot.")
            else:
                Logger.success("Traffic is normal. No defense action needed.")

        else:
            Logger.warning("Unknown action. No action applied.")

        Logger.info(f"Waiting {CHECK_INTERVAL_SECONDS} seconds before next check...")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
