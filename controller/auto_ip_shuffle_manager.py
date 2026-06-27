import argparse
import os
from datetime import datetime

from switch_manager import SwitchManager
from logger import Logger


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

    if not os.path.exists(SHUFFLE_LOG_FILE):
        with open(SHUFFLE_LOG_FILE, "w") as file:
            file.write("timestamp,active_ip,trap_ips\n")


def read_current_active_ip():
    if not os.path.exists(STATE_FILE):
        return None

    with open(STATE_FILE, "r") as file:
        value = file.read().strip()

    if value in VIRTUAL_BANK_IPS:
        return value

    return None


def save_current_active_ip(active_ip):
    with open(STATE_FILE, "w") as file:
        file.write(active_ip + "\n")


def log_shuffle(active_ip, trap_ips):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    trap_ips_text = "|".join(trap_ips)

    with open(SHUFFLE_LOG_FILE, "a") as file:
        file.write(f"{timestamp},{active_ip},{trap_ips_text}\n")


def get_next_ip():
    current_ip = read_current_active_ip()

    if current_ip is None:
        return VIRTUAL_BANK_IPS[0]

    current_index = VIRTUAL_BANK_IPS.index(current_ip)
    next_index = (current_index + 1) % len(VIRTUAL_BANK_IPS)

    return VIRTUAL_BANK_IPS[next_index]


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


def apply_ip_shuffle(active_ip):
    trap_ips = [
        ip for ip in VIRTUAL_BANK_IPS
        if ip != active_ip
    ]

    Logger.info("Starting Sequential IP Shuffling Manager...")
    Logger.info(f"Selected active bank IP: {active_ip}")

    switch_manager = SwitchManager()
    switch_manager.connect()

    Logger.info("Reloading pipeline and installing base forwarding rules...")
    switch_manager.install_forwarding_rules()

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

    print("\n========== Sequential IP Shuffling Status ==========")
    print(f"Active Bank IP : {active_ip} -> Bank Server")
    print("Trap IPs       :")

    for trap_ip in trap_ips:
        print(f"  - {trap_ip} -> Honeypot")

    print("State File     : current_active_ip.txt")
    print("Log File       : logs/ip_shuffle_log.csv")
    print("====================================================")


def main():
    parser = argparse.ArgumentParser(
        description="Sequential IP Shuffling Manager"
    )

    parser.add_argument(
        "--active-ip",
        help="Manually choose the active virtual bank IP",
        default=None
    )

    args = parser.parse_args()

    ensure_logs()

    if args.active_ip:
        if args.active_ip not in VIRTUAL_BANK_IPS:
            raise ValueError(f"Invalid active IP: {args.active_ip}")
        active_ip = args.active_ip
    else:
        active_ip = get_next_ip()

    apply_ip_shuffle(active_ip)


if __name__ == "__main__":
    main()
