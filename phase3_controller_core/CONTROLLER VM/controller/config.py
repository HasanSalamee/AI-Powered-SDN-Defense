# =========================
# P4Runtime Configuration
# =========================

P4INFO_PATH = "/home/p4/graduation_project/p4info/trust_switch.p4info.txt"
DEVICE_CONFIG_PATH = "/home/p4/graduation_project/p4info/trust_switch.json"

SWITCH_NAME = "s1"
SWITCH_ADDRESS = "192.168.43.172:50051"
DEVICE_ID = 1

# Network IP Addresses
ATTACKER_IP = "10.0.0.2"
BANK_SERVER_IP = "10.0.1.2"

ATTACKER_NETWORK = "10.0.0.0/24"
BANK_NETWORK = "10.0.1.0/24"


# =========================
# MAC Addresses
# =========================
# Attacker eth1 MAC
ATTACKER_MAC = "08:00:27:a3:99:f7"

# Bank Server eth1 MAC
BANK_SERVER_MAC = "08:00:27:28:e4:91"

# P4 Switch eth1 MAC - Port 1 side
SWITCH_ETH1_MAC = "08:00:27:b3:7e:e2"

# P4 Switch eth2 MAC - Port 2 side
SWITCH_ETH2_MAC = "08:00:27:46:ec:8a"


# =========================
# P4 Switch Ports
# =========================

PORT_TO_ATTACKER = 1
PORT_TO_BANK = 2
