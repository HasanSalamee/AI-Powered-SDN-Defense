from datetime import datetime


class Logger:

    @staticmethod
    def _timestamp():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def info(message):
        print(f"[{Logger._timestamp()}] [INFO] {message}")

    @staticmethod
    def success(message):
        print(f"[{Logger._timestamp()}] [SUCCESS] {message}")

    @staticmethod
    def warning(message):
        print(f"[{Logger._timestamp()}] [WARNING] {message}")

    @staticmethod
    def error(message):
        print(f"[{Logger._timestamp()}] [ERROR] {message}")

    @staticmethod
    def defense(message):
        print(f"[{Logger._timestamp()}] [DEFENSE] {message}")
