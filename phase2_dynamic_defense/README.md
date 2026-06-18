# Phase 2 - Dynamic Defense Controller

This phase extends the basic P4 forwarding system by adding a dynamic defense mechanism controlled by the SDN Controller.

## Main Goal

The main goal of this phase is to allow the Controller to dynamically block and unblock an attacker IP address by installing rules into a P4 blocklist table.

In Phase 1, the system was able to forward traffic between the Attacker VM and the Bank Server VM through the P4 Switch. In Phase 2, the Controller was extended to perform a simple defense action by blocking suspicious traffic based on the source IP address.

## Implemented Features

* Added a new P4 table called `blocklist`.
* The `blocklist` table matches packets based on the IPv4 source address.
* If the source IP address exists in the `blocklist`, the packet is dropped.
* If the source IP address is not blocked, normal IPv4 forwarding continues through the `ipv4_lpm` table.
* Added dynamic Controller functions:

  * `block_ip(ip_address)`
  * `unblock_ip(ip_address)`
* Added Controller scripts:

  * `block_attacker.py`
  * `unblock_attacker.py`

## Network Topology

The same topology from Phase 1 is used.

### Management Network

* Controller VM: `192.168.43.173`
* P4 Switch VM: `192.168.43.172`
* Attacker VM: `192.168.43.47`
* Bank Server VM: `192.168.43.112`

### Data Plane Network

* Attacker VM eth1: `10.0.0.2`
* P4 Switch VM eth1: `10.0.0.1`
* P4 Switch VM eth2: `10.0.1.1`
* Bank Server VM eth1: `10.0.1.2`

## P4 Switch Logic

The P4 program first checks whether the packet source IP address exists in the `blocklist` table.

If the source IP is blocked, the packet is dropped immediately.

If the source IP is not blocked, the packet continues to the normal IPv4 forwarding table `ipv4_lpm`.

The forwarding table is responsible for forwarding packets between the Attacker VM and the Bank Server VM using MAC rewrite and port selection.

## Forwarding Rules

The Controller installs the following basic forwarding rules:

* Destination `10.0.1.2/32` is forwarded to Port 2 toward the Bank Server VM.
* Destination `10.0.0.2/32` is forwarded to Port 1 toward the Attacker VM.

## Blocking Rule

The Controller can dynamically block the attacker IP address:

```bash
python3 block_attacker.py
```

This script installs a rule in the `blocklist` table to drop packets coming from:

```text
10.0.0.2
```

## Unblocking Rule

The Controller can also unblock the attacker:

```bash
python3 unblock_attacker.py
```

In this implementation, unblocking is done by resetting the pipeline and reinstalling the basic forwarding rules. This removes the blocking rule and restores normal communication.

## Tested Scenario

Before blocking, the Attacker VM can successfully reach the Bank Server VM:

```bash
ping 10.0.1.2
```

After running:

```bash
python3 block_attacker.py
```

traffic from the attacker IP `10.0.0.2` is dropped, and the ping fails.

After running:

```bash
python3 unblock_attacker.py
```

the forwarding rules are restored, and the ping works again.

## Result

This phase successfully added a dynamic defense capability to the system. The Controller is now able to control the P4 Switch and dynamically block traffic from a suspicious source IP address.

This confirms that the system can move from simple packet forwarding to active network defense.
