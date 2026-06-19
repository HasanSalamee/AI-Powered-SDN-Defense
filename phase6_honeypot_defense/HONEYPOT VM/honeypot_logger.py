import csv
import os
import subprocess
from datetime import datetime


LOG_DIR = "honeypot_logs"
LOG_FILE = os.path.join(LOG_DIR, "icmp_honeypot_log.csv")
INTERFACE = "eth1"


def ensure_log_file():
    os.makedirs(LOG_DIR, exist_ok=True)

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp",
                "source_ip",
                "destination",
                "protocol",
                "event"
            ])


def write_log(source_ip, destination, protocol, event):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            source_ip,
            destination,
            protocol,
            event
        ])


def extract_source_ip(line):
    try:
        # Example:
        # IP 10.0.0.2 > honeypot: ICMP echo request
        parts = line.split()
        if "IP" in parts:
            ip_index = parts.index("IP") + 1
            return parts[ip_index]
    except Exception:
        return None

    return None


def main():
    ensure_log_file()

    print("[HONEYPOT] Starting ICMP honeypot logger...")
    print(f"[HONEYPOT] Listening on interface: {INTERFACE}")
    print(f"[HONEYPOT] Saving logs to: {LOG_FILE}")

    command = [
        "sudo",
        "tcpdump",
        "-l",
        "-i",
        INTERFACE,
        "icmp"
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    for line in process.stdout:
        line = line.strip()

        if "ICMP echo request" in line:
            source_ip = extract_source_ip(line)

            if source_ip:
                print(f"[HONEYPOT] ICMP request detected from {source_ip}")
                write_log(
                    source_ip=source_ip,
                    destination="honeypot",
                    protocol="ICMP",
                    event="ICMP echo request"
                )


if __name__ == "__main__":
    main()
