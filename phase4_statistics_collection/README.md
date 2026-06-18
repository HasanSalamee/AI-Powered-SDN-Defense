# Phase 4 - Statistics Collection

This phase adds traffic statistics collection to the SDN/P4 defense system.

## Main Goal

The goal of this phase is to collect traffic statistics from the P4 Switch and store them in a CSV file for later use by the AI Engine.

In the previous phases, the system was able to forward traffic between the Attacker VM and the Bank Server VM, and the Controller was able to dynamically block and unblock the attacker IP address. In this phase, the system was extended to monitor traffic and collect useful packet and byte statistics from the P4 data plane.

## Implemented Features

* Added a P4 counter called `traffic_counter`.
* Added counter indexes for each traffic flow.
* Flow 1 monitors traffic from the Attacker VM to the Bank Server VM.
* Flow 2 monitors traffic from the Bank Server VM to the Attacker VM.
* The Controller reads packet and byte counters from the P4 Switch.
* Traffic statistics are displayed on the terminal.
* Traffic statistics are saved into a CSV file.
* The monitoring script connects to the P4 Switch without resetting the pipeline, so the counter values are preserved.

## Network Topology

The same topology from the previous phases is used.

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

## Network Flows

### Flow 1: Attacker to Bank Server

* Source IP: `10.0.0.2`
* Destination IP: `10.0.1.2`
* Counter index: `0`

### Flow 2: Bank Server to Attacker

* Source IP: `10.0.1.2`
* Destination IP: `10.0.0.2`
* Counter index: `1`

## P4 Program Changes

A counter was added inside the P4 program:

```p4
counter(1024, CounterType.packets_and_bytes) traffic_counter;
```

The `ipv4_forward` action was updated to accept a `counterIndex` parameter:

```p4
action ipv4_forward(
    egressSpec_t port,
    macAddr_t dstMac,
    macAddr_t srcMac,
    bit<32> counterIndex
) {
    standard_metadata.egress_spec = port;

    hdr.ethernet.dstAddr = dstMac;
    hdr.ethernet.srcAddr = srcMac;

    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    traffic_counter.count(counterIndex);
}
```

Each forwarding rule uses a different counter index, which allows the Controller to monitor each flow separately.

## Controller Changes

The Controller was updated to send a `counterIndex` value with each forwarding rule.

### Attacker to Bank Server Rule

```python
action_params={
    "port": PORT_TO_BANK,
    "dstMac": BANK_SERVER_MAC,
    "srcMac": SWITCH_ETH2_MAC,
    "counterIndex": 0
}
```

### Bank Server to Attacker Rule

```python
action_params={
    "port": PORT_TO_ATTACKER,
    "dstMac": ATTACKER_MAC,
    "srcMac": SWITCH_ETH1_MAC,
    "counterIndex": 1
}
```

## Monitoring Script

The main monitoring file is:

```bash
monitor_traffic.py
```

This script connects to the P4 Switch without resetting the pipeline, reads the counters, prints the traffic statistics, and stores them in:

```bash
logs/traffic_stats.csv
```

The script uses a runtime-only connection to avoid resetting the P4 pipeline. This is important because resetting the pipeline also resets the counter values.

## Example Test

First, the Controller installs the pipeline and forwarding rules:

```bash
python3 main.py
```

Then traffic is generated from the Attacker VM:

```bash
ping -c 5 10.0.1.2
```

After that, the monitoring script is executed:

```bash
python3 monitor_traffic.py
```

## Example Output

```text
========== Traffic Statistics ==========

Flow 1: Attacker -> Bank Server
Source: 10.0.0.2
Destination: 10.0.1.2
Packets: 5
Bytes: 490

Flow 2: Bank Server -> Attacker
Source: 10.0.1.2
Destination: 10.0.0.2
Packets: 5
Bytes: 490

========================================
```

After generating more traffic, the counters increase because they are cumulative:

```text
Flow 1: Attacker -> Bank Server
Packets: 10
Bytes: 980

Flow 2: Bank Server -> Attacker
Packets: 10
Bytes: 980
```

## CSV Output

The traffic statistics are saved in:

```bash
logs/traffic_stats.csv
```

Example CSV content:

```csv
timestamp,flow,source_ip,destination_ip,packets,bytes
2026-06-18 14:52:13,attacker_to_bank,10.0.0.2,10.0.1.2,5,490
2026-06-18 14:52:13,bank_to_attacker,10.0.1.2,10.0.0.2,5,490
2026-06-18 14:52:35,attacker_to_bank,10.0.0.2,10.0.1.2,10,980
2026-06-18 14:52:35,bank_to_attacker,10.0.1.2,10.0.0.2,10,980
```

## Important Note

The counters are cumulative. They increase as more packets pass through the P4 Switch. The counters reset only when the pipeline is reinstalled or the switch is restarted.

For this reason, the monitoring script uses `connect_runtime_only()` instead of the normal `connect()` function. This allows the Controller to read the counters without resetting the switch pipeline.

## Result

The system successfully collects traffic statistics from the P4 Switch and saves them in a CSV file.

This phase prepares the project for the next phase: AI Engine, where the collected traffic statistics will be used as input features for traffic classification and attack detection.
