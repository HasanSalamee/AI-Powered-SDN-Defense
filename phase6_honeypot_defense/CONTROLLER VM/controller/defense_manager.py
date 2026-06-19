from config import ATTACKER_IP
from logger import Logger

class DefenseManager:

    def __init__(self, switch_manager):
        self.switch_manager = switch_manager

    def block_attacker(self):
        """
        Block the attacker IP by installing a rule
        in the P4 blocklist table.
        """
        print(" Defense action: Blocking attacker")

        self.switch_manager.block_ip(ATTACKER_IP)

        print(f" Attacker blocked: {ATTACKER_IP}")

    def unblock_attacker(self):
        """
        Unblock the attacker by resetting the pipeline
        and reinstalling the normal forwarding rules.
        """
        print(" Defense action: Unblocking attacker")

        self.switch_manager.install_forwarding_rules()

        print(f" Attacker unblocked: {ATTACKER_IP}")
    def redirect_attacker_to_honeypot(self):
        Logger.defense("Defense action: Redirecting attacker to honeypot")
        self.switch_manager.redirect_ip_to_honeypot(ATTACKER_IP)
        Logger.defense(f"Attacker redirected to honeypot: {ATTACKER_IP}")
