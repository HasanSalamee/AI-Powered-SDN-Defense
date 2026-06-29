#!/bin/bash

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: ./web_attack_test.sh <target-ip>"
    echo "Example: ./web_attack_test.sh 10.0.1.2"
    exit 1
fi

echo "======================================"
echo "Starting Web Attack Simulation"
echo "Target: $TARGET"
echo "======================================"

echo "[1] Normal page access"
curl -s -A "Mozilla/5.0" http://$TARGET:8080/ > /dev/null
echo "Done"

echo "[2] Admin panel probing"
curl -s -A "Mozilla/5.0" http://$TARGET:8080/admin > /dev/null
echo "Done"

echo "[3] Sensitive file probing"
curl -s -A "curl-attacker" http://$TARGET:8080/.env > /dev/null
echo "Done"

echo "[4] Fake login attempt"
curl -s -X POST http://$TARGET:8080/login \
  -A "curl-attacker" \
  -d "username=admin&password=123456" > /dev/null
echo "Done"

echo "[5] Scanner-like request"
curl -s -A "sqlmap" http://$TARGET:8080/login?id=1 > /dev/null
echo "Done"

echo "======================================"
echo "Web Attack Simulation Finished"
echo "======================================"
