import sys

sys.path.append("/home/p4/tutorials/utils")

import p4runtime_lib.bmv2
import p4runtime_lib.helper


class SwitchManager:

    def __init__(self):
        self.p4info_path = "/home/p4/graduation_project/p4info/trust_switch.p4info.txt"
        self.device_config_path = "/home/p4/graduation_project/p4info/trust_switch.json"

        self.switch = None
        self.helper = None

    def connect(self):
        print("Loading P4Info...")

        self.helper = p4runtime_lib.helper.P4InfoHelper(
            self.p4info_path
        )

        print("Connecting to switch...")

        self.switch = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name="s1",
            address="192.168.43.172:50051",
            device_id=1
        )

        self.switch.MasterArbitrationUpdate()

        self.switch.SetForwardingPipelineConfig(
            p4info=self.helper.p4info,
            bmv2_json_file_path=self.device_config_path
        )

        print("✅ Pipeline installed")
        print("✅ Connected to P4 Switch")

        return self.switch

    def install_forwarding_rules(self):

        # Attacker -> Bank
        table_entry1 = self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ("10.0.1.2", 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": 2,
                "dstMac": "08:00:27:28:e4:91",
                "srcMac": "08:00:27:46:ec:8a"
            }
        )

        self.switch.WriteTableEntry(table_entry1)

        # Bank -> Attacker
        table_entry2 = self.helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": ("10.0.0.2", 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "port": 1,
                "dstMac": "08:00:27:a3:99:f7",
                "srcMac": "08:00:27:b3:7e:e2"
            }
        )

        self.switch.WriteTableEntry(table_entry2)

        print("✅ Forwarding rules installed")

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

        print(f"🚫 Blocked IP: {ip_address}")

    def unblock_ip(self, ip_address):

        table_entry = self.helper.buildTableEntry(
            table_name="MyIngress.blocklist",
            match_fields={
                "hdr.ipv4.srcAddr": ip_address
            },
            action_name="MyIngress.drop",
            action_params={}
        )

        self.switch.DeleteTableEntry(table_entry)

        print(f"✅ Unblocked IP: {ip_address}")
