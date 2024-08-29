#!/bin/bash
echo "Starting Snort"
ifconfig ids-eth0 promisc
echo "Setting interface to promisc mode"
nohup snort -A unsock -i ids-eth0 -l /tmp -c /etc/snort/snort.conf -k none &
echo "Snort daemon running"
python3 pigrelay.py