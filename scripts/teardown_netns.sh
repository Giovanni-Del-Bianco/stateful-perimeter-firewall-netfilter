#!/bin/bash
# ==============================================================================
# Teardown Virtual Topology and Reset Netfilter Policies to Default ACCEPT
# ==============================================================================

# Kill mock listeners
for pidfile in /tmp/fw_mock_ssh.pid /tmp/dmz_http.pid /tmp/ext_http.pid; do
    if [ -f "$pidfile" ]; then
        kill -9 "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    fi
done

# Delete namespaces
ip netns del ns-lan-admin 2>/dev/null || true
ip netns del ns-lan-user 2>/dev/null || true
ip netns del ns-dmz 2>/dev/null || true
ip netns del ns-ext 2>/dev/null || true

# Delete host virtual interfaces and bridge
ip link del eth0 2>/dev/null || true
ip link del eth1 2>/dev/null || true
ip link del eth2 2>/dev/null || true
ip link del br-lan 2>/dev/null || true

# Reset iptables policies to ACCEPT and flush tables
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -t filter -F
iptables -t nat -F
iptables -t mangle -F

echo "[CLEAN] Virtual topology removed and iptables rules reset to ACCEPT."

