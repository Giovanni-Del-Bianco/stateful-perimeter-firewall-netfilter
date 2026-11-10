#!/bin/bash
# ==============================================================================
# Virtual Topology Provisioner using Linux Network Namespaces (ip netns)
# Simulates LAN (Switch + Admin + User), DMZ (Web Server), and EXT (Internet)
# ==============================================================================

set -e

echo "[NETNS] Cleaning up any previous virtual topology..."
./scripts/teardown_netns.sh >/dev/null 2>&1 || true

echo "[NETNS] Creating isolated Network Namespaces..."
ip netns add ns-lan-admin
ip netns add ns-lan-user
ip netns add ns-dmz
ip netns add ns-ext

echo "[NETNS] Creating LAN virtual switch (br-lan) and veth interfaces..."
# Create a virtual bridge for the LAN segment so both Admin (100.2) and User (100.3) share eth0
ip link add br-lan type bridge
ip link set br-lan up

ip link add eth0 type veth peer name br-eth0
ip link set br-eth0 master br-lan
ip link set br-eth0 up

ip link add veth-admin type veth peer name br-admin
ip link set br-admin master br-lan
ip link set br-admin up
ip link set veth-admin netns ns-lan-admin

ip link add veth-user type veth peer name br-user
ip link set br-user master br-lan
ip link set br-user up
ip link set veth-user netns ns-lan-user

# Create DMZ (eth1) and EXT (eth2) point-to-point veth pairs
ip link add eth1 type veth peer name veth-dmz
ip link set veth-dmz netns ns-dmz

ip link add eth2 type veth peer name veth-ext
ip link set veth-ext netns ns-ext

echo "[NETNS] Assigning Firewall gateway IPv4 addresses (eth0, eth1, eth2)..."
ip addr add 192.168.100.1/24 dev eth0
ip link set eth0 up

ip addr add 192.168.101.1/24 dev eth1
ip link set eth1 up

ip addr add 192.168.102.1/24 dev eth2
ip link set eth2 up

echo "[NETNS] Configuring namespace hosts and default gateways..."
# LAN Admin (192.168.100.2)
ip netns exec ns-lan-admin ip link set lo up
ip netns exec ns-lan-admin ip addr add 192.168.100.2/24 dev veth-admin
ip netns exec ns-lan-admin ip link set veth-admin up
ip netns exec ns-lan-admin ip route add default via 192.168.100.1

# LAN Standard User (192.168.100.3)
ip netns exec ns-lan-user ip link set lo up
ip netns exec ns-lan-user ip addr add 192.168.100.3/24 dev veth-user
ip netns exec ns-lan-user ip link set veth-user up
ip netns exec ns-lan-user ip route add default via 192.168.100.1

# DMZ Web Server (192.168.101.2)
ip netns exec ns-dmz ip link set lo up
ip netns exec ns-dmz ip addr add 192.168.101.2/24 dev veth-dmz
ip netns exec ns-dmz ip link set veth-dmz up
ip netns exec ns-dmz ip route add default via 192.168.101.1

# EXT Host (192.168.102.2)
ip netns exec ns-ext ip link set lo up
ip netns exec ns-ext ip addr add 192.168.102.2/24 dev veth-ext
ip netns exec ns-ext ip link set veth-ext up
ip netns exec ns-ext ip route add default via 192.168.102.1

echo "[NETNS] Starting mock services (SSH listener on Firewall, HTTP servers in DMZ & EXT)..."
# Start a lightweight TCP listener on Firewall port 22 if sshd is not running on 192.168.100.1
if ! ss -tln | grep -q ":22 "; then
    nohup nc -lk -p 22 >/dev/null 2>&1 &
    echo $! > /tmp/fw_mock_ssh.pid
fi

# Start HTTP server inside DMZ (192.168.101.2:80)
ip netns exec ns-dmz nohup python3 -m http.server 80 >/dev/null 2>&1 &
echo $! > /tmp/dmz_http.pid

# Start HTTP server inside EXT (192.168.102.2:80) to test outbound LAN -> EXT HTTP & SNAT
ip netns exec ns-ext nohup python3 -m http.server 80 >/dev/null 2>&1 &
echo $! > /tmp/ext_http.pid

sleep 1
echo "[SUCCESS] Virtual three-tier topology is active."

