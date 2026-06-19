#!/bin/bash

sudo simple_switch_grpc \
-i 1@eth1 \
-i 2@eth2 \
-i 3@eth3 \
--device-id 1 \
../build/trust_switch.json \
--thrift-port 9090 \
--log-console \
-- \
--grpc-server-addr 0.0.0.0:50051 \
--cpu-port 255
