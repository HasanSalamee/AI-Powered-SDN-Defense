# Phase 5 - AI Engine

This phase adds an AI-based traffic detection engine to the SDN/P4 defense system.

## Main Goal

The goal of this phase is to analyze the traffic statistics collected in Phase 4 and classify the traffic as normal, suspicious, or malicious.

The AI Engine reads the traffic statistics from:

```bash
logs/traffic_stats.csv

Then it stores the detection results in:

logs/ai_detection_log.csv
Implemented Features
Created an AI detection module.
Added rule-based traffic classification.
Classified traffic into:
normal
suspicious
malicious
Added recommended actions:
allow
monitor
block
Connected the AI decision with the defense controller.
Automatically blocked the attacker when malicious traffic was detected.
Detection Logic

The current AI Engine uses a simple rule-based detection logic:

packets < 20      → normal      → allow
packets < 100     → suspicious  → monitor
packets >= 100    → malicious   → block

This logic will be improved later using a real machine learning model.

Main Files
AI Detector
controller/ai/ai_detector.py

This file reads traffic statistics and classifies each flow.

AI Defense Controller
controller/ai_defense_controller.py

This file reads the latest AI decision and applies the required defense action.

Statistics Input
controller/logs/traffic_stats.csv

This file contains traffic statistics collected from the P4 Switch.

AI Output Log
controller/logs/ai_detection_log.csv

This file stores the AI classification results.

Example Detection Result
Flow: attacker_to_bank
Source IP: 10.0.0.2
Destination IP: 10.0.1.2
Packets: 151
Bytes: 14798
Classification: malicious
Recommended Action: block
Example Defense Action
AI recommended blocking the attacker
Blocked IP: 10.0.0.2
AI-based blocking action completed
Result

The system successfully analyzed traffic statistics, classified malicious traffic, and automatically blocked the attacker using the SDN Controller.

This phase proves the full chain:

Traffic Statistics
        ↓
AI Detection
        ↓
AI Decision
        ↓
Defense Action
        ↓
Block Attacker
Next Phase

The next phase is Phase 6: Trust-Based Defense / Honeypot
