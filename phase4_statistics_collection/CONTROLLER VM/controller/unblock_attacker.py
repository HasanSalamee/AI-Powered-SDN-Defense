from switch_manager import SwitchManager
from defense_manager import DefenseManager


def main():
    switch_manager = SwitchManager()

    switch_manager.connect()

    defense_manager = DefenseManager(switch_manager)

    defense_manager.unblock_attacker()


if __name__ == "__main__":
    main()
