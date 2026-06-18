from switch_manager import SwitchManager
from defense_manager import DefenseManager


def main():
    switch_manager = SwitchManager()

    switch_manager.connect()

    switch_manager.install_forwarding_rules()

    defense_manager = DefenseManager(switch_manager)

    defense_manager.block_attacker()


if __name__ == "__main__":
    main()
