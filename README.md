# AI-Powered SDN/P4 Defense System

This project implements a programmable SDN/P4-based defense system for a bank network.

## Main Features

- P4-based packet forwarding using BMv2
- Real-time traffic counters
- Rule-based AI risk scoring
- Moving Target Defense using periodic IP Shuffling
- Inactive bank IPs are dropped
- Medium-risk traffic triggers immediate IP Shuffling
- High/Critical-risk traffic is redirected to a Honeypot
- Fake Bank Honeypot records attacker behavior
- Web Dashboard shows ACTIVE / DROPPED virtual bank IPs

## Virtual Bank IP Pool

Only one bank IP is active at a time:

- 10.0.1.100
- 10.0.1.101
- 10.0.1.102

Inactive IPs are dropped by the P4 switch.

## Defense Policy

| Risk Level | Defense Action |
|---|---|
| Normal | Periodic IP Shuffling every 30 seconds |
| Medium / Suspicious | Immediate IP Shuffling + drop old IPs |
| High / Critical | Redirect attacker to Honeypot |

## Main Components

- `p4/trust_switch.p4`  
  P4 data plane program.

- `runtime/start_switch.sh`  
  Starts the BMv2 P4 switch.

- `controller/auto_defense_loop_final.py`  
  Final controller defense loop.

- `controller/restore_normal_forwarding.py`  
  Restores normal forwarding rules.

- `web_demo/demo_web_dashboard.py`  
  Web dashboard for visualizing active and dropped bank IPs.

- `scripts/web_attack_test.sh`  
  Simulated web attack script.

## Final Demo

See:

```text
docs/FINAL_DEMO_STEPS.md
