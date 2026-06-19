from switch_manager import SwitchManager


def main():
    manager = SwitchManager()

    manager.connect()

    manager.install_forwarding_rules()


if __name__ == "__main__":
    main()
