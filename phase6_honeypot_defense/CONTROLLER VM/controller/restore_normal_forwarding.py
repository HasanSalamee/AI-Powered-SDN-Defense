from switch_manager import SwitchManager
from logger import Logger


def main():
    Logger.info("Restoring normal forwarding state...")

    switch_manager = SwitchManager()
    switch_manager.connect()
    switch_manager.install_forwarding_rules()

    Logger.success("Normal forwarding restored")
    Logger.success("Redirect rules removed because pipeline was reinstalled")


if __name__ == "__main__":
    main()
