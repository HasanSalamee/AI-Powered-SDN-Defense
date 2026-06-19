import sys

sys.path.append("/home/p4/tutorials/utils")

import p4runtime_lib.bmv2
import p4runtime_lib.helper

from config import (
    P4INFO_PATH,
    DEVICE_CONFIG_PATH,
    SWITCH_NAME,
    SWITCH_ADDRESS,
    DEVICE_ID,
    ATTACKER_IP,
    BANK_SERVER_IP,
    ATTACKER_MAC,
    BANK_SERVER_MAC,
    SWITCH_ETH1_MAC,
    SWITCH_ETH2_MAC,
    PORT_TO_ATTACKER,
    PORT_TO_BANK,
    HONEYPOT_IP,
    HONEYPOT_MAC,
    SWITCH_ETH3_MAC,
    PORT_TO_HONEYPOT,
)

from logger import Logger


class SwitchManager:

    def __init__(self):
        self.p4info_path = P4INFO_PATH
        self.device_config_path = DEVICE_CONFIG_PATH
        self.switch = None
        self.helper = None

    def connect(self):
        Logger.info("Loading P4Info...")

        self.helper = p4runtime_lib.helper.P4InfoHelper(
            self.p4info_path
        )

        Logger.info("Connecting to P4 Switch...")

        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=SWITCH_NAME,
            address=SWITCH_ADDRESS,
            device_id=DEVICE_ID
        )

        self.switch.MasterArbitrationUpdate()

        self.switch.SetForwardingPipelineConfig(
            p4info=self.helper.p4info,
            bmv2_json_file_path=self.device_config_path
        )

        Logger.success("Pipeline installed")
        Logger.success("Connected to P4 Switch")

        return self.switch

    def connect_runtime_only(self):
        Logger.info("Loading P4Info...")

        self.helper = p4runtime_lib.helper.P4InfoHelper(
            self.p4info_path
        )

        Logger.info("Connecting to P4 Switch without pipeline reset...")

        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=SWITCH_NAME,
            address=SWITCH_ADDRESS,
            device_id=DEVICE_ID
        )

        self.switch.MasterArbitrationUpdate()

        Logger.success("Connected to P4 Switch without resetting pipeline")

        return self.switch
    def install_forwarding_rules(self):

        # Attacker -> Bank Server
        table_entry1 = self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (BANK_SERVER_IP, 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": PORT_TO_BANK,
                "dstMac": BANK_SERVER_MAC,
                "srcMac": SWITCH_ETH2_MAC,
		"counterIndex": 0
            }
        )

        self.switch.WriteTableEntry(table_entry1)

        # Bank Server -> Attacker
        table_entry2 = self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (ATTACKER_IP, 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": PORT_TO_ATTACKER,
                "dstMac": ATTACKER_MAC,
                "srcMac": SWITCH_ETH1_MAC,
		"counterIndex": 1
            }
        )

        self.switch.WriteTableEntry(table_entry2)

        Logger.success("Forwarding rules installed")

    def block_ip(self, ip_address):

        table_entry = self.helper.buildTableEntry(
            table_name="MyIngress.blocklist",
            match_fields={
                "hdr.ipv4.srcAddr": ip_address
            },
            action_name="MyIngress.drop",
            action_params={}
        )

        self.switch.WriteTableEntry(table_entry)

        Logger.defense(f"Blocked IP: {ip_address}")
    def redirect_ip_to_honeypot(self, ip_address):
        table_entry = self.helper.buildTableEntry(
            table_name="MyIngress.honeypot_redirect",
            match_fields={
                "hdr.ipv4.srcAddr": ip_address
            },
            action_name="MyIngress.redirect_to_honeypot",
            action_params={
                "port": PORT_TO_HONEYPOT,
                "dstMac": HONEYPOT_MAC,
                "srcMac": SWITCH_ETH3_MAC,
                "honeypotIp": HONEYPOT_IP,
                "counterIndex": 2
            }
        )

        self.switch.WriteTableEntry(table_entry)
        Logger.defense(f"Redirected IP to honeypot: {ip_address}")
