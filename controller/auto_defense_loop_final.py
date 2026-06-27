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

# كل 30 ثانية يتغير Active Bank IP حتى لو الترافيك طبيعي
PERIODIC_SHUFFLE_SECONDS = 30

# إذا صار medium risk، لا يعمل shuffle أكثر من مرة كل 12 ثانية
SHUFFLE_COOLDOWN_SECONDS = 12

TRAFFIC_STATS_FILE = "logs/traffic_stats.csv"
AI_LOG_FILE = "logs/ai_detection_log.csv"
SHUFFLE_LOG_FILE = "logs/ip_shuffle_log.csv"
STATE_FILE = "current_active_ip.txt"

HONEYPOT_IP = "10.0.2.2"

VIRTUAL_BANK_IPS = [
    "10.0.1.100",
    "10.0.1.101",
    "10.0.1.102"
]

BANK_SERVER_MAC = "08:00:27:28:e4:91"
SWITCH_ETH2_MAC = "08:00:27:46:ec:8a"

HONEYPOT_MAC = "08:00:27:72:ea:d0"
SWITCH_ETH3_MAC = "08:00:27:3c:7f:0e"

PORT_TO_BANK = 2


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
                "defense_action",
                "reason"
            ])

    if not os.path.exists(SHUFFLE_LOG_FILE):
        with open(SHUFFLE_LOG_FILE, mode="w") as file:
            file.write("timestamp,active_ip,dropped_ips,mode\n")


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


def save_ai_result(
    flow,
    source_ip,
    destination_ip,
    packets,
    bytes_count,
    ai_result,
    defense_action
):
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
            defense_action,
            ai_result["reason"]
        ])


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


def log_shuffle(active_ip, dropped_ips, mode):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dropped_ips_text = "|".join(dropped_ips)

    with open(SHUFFLE_LOG_FILE, "a") as file:
        file.write(f"{timestamp},{active_ip},{dropped_ips_text},{mode}\n")


def delete_lpm_forward_or_drop(switch_manager, dst_ip, prefix_len):
    """
    نحاول نحذف أي entry قديم لنفس الـ IP.
    أحياناً يكون القديم forward وأحياناً drop.
    لذلك نجرب الاثنين ونتجاهل الخطأ.
    """

    try:
        forward_entry = switch_manager.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip, prefix_len)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": PORT_TO_BANK,
                "dstMac": BANK_SERVER_MAC,
                "srcMac": SWITCH_ETH2_MAC,
                "counterIndex": 0
            }
        )
        switch_manager.switch.DeleteTableEntry(forward_entry)
    except Exception:
        pass

    try:
        drop_entry = switch_manager.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip, prefix_len)
            },
            action_name="MyIngress.drop",
            action_params={}
        )
        switch_manager.switch.DeleteTableEntry(drop_entry)
    except Exception:
        pass


def install_lpm_forward(
    switch_manager,
    dst_ip,
    prefix_len,
    port,
    dst_mac,
    src_mac,
    counter_index
):
    delete_lpm_forward_or_drop(switch_manager, dst_ip, prefix_len)

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


def install_lpm_drop(switch_manager, dst_ip, prefix_len):
    delete_lpm_forward_or_drop(switch_manager, dst_ip, prefix_len)

    table_entry = switch_manager.helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip, prefix_len)
        },
        action_name="MyIngress.drop",
        action_params={}
    )

    switch_manager.switch.WriteTableEntry(table_entry)


def apply_moving_target_defense(switch_manager, mode):
    """
    Moving Target Defense:
    - يختار IP جديد من pool
    - الجديد يذهب إلى Real Bank
    - القديم والباقي DROP
    - لا Honeypot في هذه المرحلة
    """

    active_ip = get_next_active_ip()

    dropped_ips = [
        ip for ip in VIRTUAL_BANK_IPS
        if ip != active_ip
    ]

    Logger.defense("Applying Moving Target Defense: IP Shuffling + Drop old IPs")
    Logger.info(f"New active bank IP: {active_ip}")

    for virtual_ip in VIRTUAL_BANK_IPS:
        if virtual_ip == active_ip:
            install_lpm_forward(
                switch_manager=switch_manager,
                dst_ip=virtual_ip,
                prefix_len=32,
                port=PORT_TO_BANK,
                dst_mac=BANK_SERVER_MAC,
                src_mac=SWITCH_ETH2_MAC,
                counter_index=0
            )

            Logger.success(f"ACTIVE: {virtual_ip} -> Real Bank Server")

        else:
            install_lpm_drop(
                switch_manager=switch_manager,
                dst_ip=virtual_ip,
                prefix_len=32
            )

            Logger.warning(f"DROPPED: {virtual_ip} -> No Bank, No Honeypot")

    save_current_active_ip(active_ip)
    log_shuffle(active_ip, dropped_ips, mode)

    print("\n========== Moving Target Defense Applied ==========")
    print(f"Mode           : {mode}")
    print(f"Active Bank IP : {active_ip} -> Real Bank Server")
    print("Dropped Old IPs:")
    for dropped_ip in dropped_ips:
        print(f"  - {dropped_ip} -> DROP")
    print("===================================================")

    return active_ip


def print_ai_result(active_flow, packets, bytes_count, ai_result, defense_action):
    print("\n========== Rule-Based AI ==========")
    print(f"Active Flow: {active_flow}")
    print(f"Packets: {packets}")
    print(f"Bytes: {bytes_count}")
    print(f"Risk Score: {ai_result['risk_score']}/100")
    print(f"Classification: {ai_result['classification']}")
    print(f"Recommended Action: {ai_result['recommended_action']}")
    print(f"Defense Action: {defense_action}")
    print(f"Reason: {ai_result['reason']}")
    print("===================================")


def print_counters(packets_bank, bytes_bank, packets_honeypot, bytes_honeypot):
    print("\n========== Counters ==========")
    print(f"Bank Path Packets: {packets_bank}")
    print(f"Bank Path Bytes: {bytes_bank}")
    print(f"Honeypot Packets: {packets_honeypot}")
    print(f"Honeypot Bytes: {bytes_honeypot}")
    print("==============================")


def main():
    Logger.info("Starting FINAL Auto Defense Loop...")
    Logger.info("Policy 1: Normal traffic -> Periodic IP Shuffling every 30 seconds")
    Logger.info("Policy 2: Medium risk -> Immediate IP Shuffling + Drop old IPs")
    Logger.info("Policy 3: High/Critical risk -> Redirect attacker to Honeypot")

    ensure_logs()

    switch_manager = SwitchManager()
    switch_manager.connect()
    switch_manager.install_forwarding_rules()

    defense_manager = DefenseManager(switch_manager)
    ai_detector = AdvancedAIDetector()

    redirected = False

    # أول تشغيل: نعمل active IP من pool ونخلي الباقي drop
    apply_moving_target_defense(
        switch_manager=switch_manager,
        mode="initial-startup-shuffle"
    )

    last_shuffle_time = time.time()
    last_periodic_shuffle_time = time.time()

    Logger.success("Initial pipeline and forwarding rules installed")
    Logger.info("Final auto defense loop is running")

    while True:
        packets_bank, bytes_bank = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            0
        )

        packets_bank_to_attacker, bytes_bank_to_attacker = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            1
        )

        packets_honeypot, bytes_honeypot = read_counter(
            switch_manager,
            "MyIngress.traffic_counter",
            2
        )

        save_traffic_stats(
            "attacker_to_bank",
            ATTACKER_IP,
            BANK_SERVER_IP,
            packets_bank,
            bytes_bank
        )

        save_traffic_stats(
            "bank_to_attacker",
            BANK_SERVER_IP,
            ATTACKER_IP,
            packets_bank_to_attacker,
            bytes_bank_to_attacker
        )

        save_traffic_stats(
            "attacker_to_honeypot",
            ATTACKER_IP,
            HONEYPOT_IP,
            packets_honeypot,
            bytes_honeypot
        )

        if redirected:
            active_flow = "attacker_to_honeypot"
            active_packets = packets_honeypot
            active_bytes = bytes_honeypot
        else:
            active_flow = "attacker_to_bank"
            active_packets = packets_bank
            active_bytes = bytes_bank

        ai_result = ai_detector.analyze(
            current_packets=active_packets,
            current_bytes=active_bytes
        )

        recommended_action = ai_result["recommended_action"]
        defense_action = "allow"

        current_time = time.time()

        # 1) High/Critical: أعلى أولوية
        if recommended_action == "redirect" and not redirected:
            defense_action = "redirect_to_honeypot"

            Logger.defense("High/Critical risk detected.")
            Logger.defense("Redirecting attacker to Honeypot")

            defense_manager.redirect_attacker_to_honeypot()
            redirected = True

            Logger.success("Attacker traffic is now redirected to Honeypot")

        # 2) إذا صار redirect من قبل، نراقب الهاني بوت فقط
        elif redirected:
            defense_action = "already_redirected_monitor_honeypot"

        # 3) Medium/Suspicious: IP Shuffle مباشر فقط، بدون Honeypot
        elif recommended_action == "monitor":
            if current_time - last_shuffle_time >= SHUFFLE_COOLDOWN_SECONDS:
                defense_action = "medium_risk_ip_shuffle_drop_old_ips"

                apply_moving_target_defense(
                    switch_manager=switch_manager,
                    mode="medium-risk-shuffle"
                )

                last_shuffle_time = current_time
                last_periodic_shuffle_time = current_time
            else:
                defense_action = "medium_risk_wait_cooldown"

        # 4) Normal: كل 30 ثانية IP Shuffle دوري
        else:
            if current_time - last_periodic_shuffle_time >= PERIODIC_SHUFFLE_SECONDS:
                defense_action = "periodic_ip_shuffle_drop_old_ips"

                apply_moving_target_defense(
                    switch_manager=switch_manager,
                    mode="periodic-30-seconds-shuffle"
                )

                last_periodic_shuffle_time = current_time
                last_shuffle_time = current_time
            else:
                defense_action = "allow"

        save_ai_result(
            active_flow,
            ATTACKER_IP,
            HONEYPOT_IP if redirected else BANK_SERVER_IP,
            active_packets,
            active_bytes,
            ai_result,
            defense_action
        )

        print_ai_result(
            active_flow,
            active_packets,
            active_bytes,
            ai_result,
            defense_action
        )

        print_counters(
            packets_bank,
            bytes_bank,
            packets_honeypot,
            bytes_honeypot
        )

        current_active_ip = read_current_active_ip()
        print("\n========== Current Bank IP State ==========")
        print(f"Current Active Bank IP: {current_active_ip}")
        print("Virtual Bank IP Pool:")
        for ip in VIRTUAL_BANK_IPS:
            if ip == current_active_ip:
                print(f"  - {ip} -> ACTIVE BANK")
            else:
                print(f"  - {ip} -> DROP")
        print("===========================================")

        if defense_action == "allow":
            Logger.success("Traffic is normal. Waiting for periodic shuffle timer.")

        elif defense_action == "periodic_ip_shuffle_drop_old_ips":
            Logger.defense("Periodic Moving Target Defense executed.")

        elif defense_action == "medium_risk_ip_shuffle_drop_old_ips":
            Logger.defense("Medium risk handled with IP Shuffling only. No Honeypot redirect.")

        elif defense_action == "medium_risk_wait_cooldown":
            Logger.warning("Medium risk detected, but shuffle cooldown is active.")

        elif defense_action == "redirect_to_honeypot":
            Logger.defense("High/Critical risk handled with Honeypot redirect.")

        elif defense_action == "already_redirected_monitor_honeypot":
            Logger.warning("Attacker already redirected. Monitoring Honeypot traffic.")

        Logger.info(f"Waiting {CHECK_INTERVAL_SECONDS} seconds before next check...")
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
