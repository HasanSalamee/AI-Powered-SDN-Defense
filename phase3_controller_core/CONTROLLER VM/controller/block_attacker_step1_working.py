from switch_manager import SwitchManager
from config import ATTACKER_IP


def main():
    manager = SwitchManager()

    manager.connect()

    manager.install_forwarding_rules()

    manager.block_ip(ATTACKER_IP)


if __name__ == "__main__":
    main()
