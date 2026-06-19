import csv
import os

from switch_manager import SwitchManager
from defense_manager import DefenseManager
from logger import Logger
from config import ATTACKER_IP


AI_LOG_FILE = "logs/ai_detection_log.csv"


def get_latest_attacker_decision():
    if not os.path.exists(AI_LOG_FILE):
        Logger.error(f"AI log file not found: {AI_LOG_FILE}")
        return None

    latest_decision = None

    with open(AI_LOG_FILE, mode="r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            if row["source_ip"] == ATTACKER_IP:
                latest_decision = row

    return latest_decision


def main():
    Logger.info("Starting AI-based defense controller...")

    decision = get_latest_attacker_decision()

    if decision is None:
        Logger.warning("No AI decision found for attacker")
        return

    classification = decision["classification"]
    recommended_action = decision["recommended_action"]
    packets = decision["packets"]
    bytes_count = decision["bytes"]

    print("\n========== Latest AI Decision ==========")
    print(f"Source IP: {decision['source_ip']}")
    print(f"Destination IP: {decision['destination_ip']}")
    print(f"Packets: {packets}")
    print(f"Bytes: {bytes_count}")
    print(f"Classification: {classification}")
    print(f"Recommended Action: {recommended_action}")
    print("=======================================\n")

    if recommended_action == "redirect":
        Logger.defense("AI recommended blocking the attacker")

        switch_manager = SwitchManager()
        switch_manager.connect()
        switch_manager.install_forwarding_rules()

        defense_manager = DefenseManager(switch_manager)
        defense_manager.redirect_attacker_to_honeypot()

        Logger.success("AI-based honeypot redirect completed")

    elif recommended_action == "monitor":
        Logger.warning("AI recommended monitoring the attacker")

    else:
        Logger.success("AI classified traffic as normal. No action needed.")


if __name__ == "__main__":
    main()
