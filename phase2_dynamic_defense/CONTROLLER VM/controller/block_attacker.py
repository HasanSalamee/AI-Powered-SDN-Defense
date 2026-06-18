from switch_manager import SwitchManager


def main():
    manager = SwitchManager()

    manager.connect()

    manager.install_forwarding_rules()

    manager.block_ip("10.0.0.2")


if __name__ == "__main__":
    main()
