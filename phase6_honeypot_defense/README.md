# Phase 6 - Honeypot Defense

This phase adds Honeypot-based defense to the SDN/P4 security system.

## Main Goal

The goal of this phase is to redirect malicious traffic to a Honeypot instead of only blocking it.

When the AI Engine detects malicious traffic, the SDN Controller installs a redirect rule in the P4 Switch. This rule redirects the attacker traffic away from the real Bank Server and sends it to the Honeypot.

## Network Design

### P4 Switch Interfaces

- eth0: Management network
- eth1: Attacker side
- eth2: Bank Server side
- eth3: Honeypot side

### Data Plane IP Addresses

- Attacker VM: `10.0.0.2`
- P4 Switch eth1: `10.0.0.1`
- Bank Server VM: `10.0.1.2`
- P4 Switch eth2: `10.0.1.1`
- Honeypot VM: `10.0.2.2`
- P4 Switch eth3: `10.0.2.1`

## Implemented Features

- Added Honeypot VM to the topology.
- Added a third data-plane interface on the P4 Switch.
- Added Port 3 to `simple_switch_grpc`.
- Added Honeypot configuration values in `config.py`.
- Added `redirect_to_honeypot` action in the P4 program.
- Added `honeypot_redirect` table in the P4 program.
- Added Controller support for redirecting attacker traffic.
- Updated the AI Defense Controller to redirect malicious traffic to the Honeypot.
- Added Honeypot logging using `honeypot_logger.py`.
- Added a restore script to return the network to normal forwarding.

## P4 Changes

A new action was added:

```p4
redirect_to_honeypot(...)

This action rewrites the destination IP address to the Honeypot IP, rewrites the Ethernet MAC addresses, sends the packet to Port 3, and updates the traffic counter.

A new table was also added:

honeypot_redirect

This table matches on the attacker source IP address and redirects the traffic to the Honeypot.

Controller Changes

The Controller now supports:

redirect_ip_to_honeypot(ip_address)

inside switch_manager.py.

The defense_manager.py file also includes:

redirect_attacker_to_honeypot()

The AI Defense Controller now applies:

malicious → redirect

instead of only blocking the attacker.

Honeypot Logging

The Honeypot VM runs:

python3 ~/honeypot_logger.py

The logger captures ICMP traffic using tcpdump and saves attack logs to:

honeypot_logs/icmp_honeypot_log.csv
Example Result

When the attacker sends traffic to the Bank Server:

ping 10.0.1.2

The P4 Switch redirects the traffic to the Honeypot.

On the Honeypot, tcpdump showed:

10.0.0.2 > honeypot: ICMP echo request
honeypot > 10.0.0.2: ICMP echo reply

This proves that malicious traffic was redirected to the Honeypot instead of reaching the real Bank Server.

Restore Normal Forwarding

To remove redirect rules and restore normal forwarding:

python3 restore_normal_forwarding.py

This reloads the P4 pipeline and reinstalls the normal forwarding rules.

Result

The system successfully redirects malicious traffic to the Honeypot and logs the attack traffic in a CSV file.

This completes the Honeypot Defense phase.
