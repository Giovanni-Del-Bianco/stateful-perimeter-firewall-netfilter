#!/bin/bash
# ==============================================================================
# Automated 9-Case Security Policy Verification Matrix
# ==============================================================================

PASS_COUNT=0
FAIL_COUNT=0

check_pass() {
    local desc="$1"
    shift
    printf "%-62s " "$desc"
    if "$@" >/dev/null 2>&1; then
        echo "[ PASS ]"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[ FAIL ]"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

check_block() {
    local desc="$1"
    shift
    printf "%-62s " "$desc"
    if ! "$@" >/dev/null 2>&1; then
        echo "[ PASS ]"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[ FAIL ]"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

echo "======================================================================"
echo " LINUX NETFILTER PERIMETER FIREWALL - AUTOMATED VERIFICATION SUITE"
echo "======================================================================"

# 1. LAN Admin -> Firewall ICMP Ping (Expected: Allowed)
check_pass "[TEST 01] LAN Admin -> Firewall ICMP Ping" \
    ip netns exec ns-lan-admin ping -c 1 -W 1 192.168.100.1

# 2. EXT Host -> Firewall ICMP Ping (Expected: Blocked)
check_block "[TEST 02] EXT Host  -> Firewall ICMP Ping (Stealth Drop)" \
    ip netns exec ns-ext ping -c 1 -W 1 192.168.102.1

# 3. LAN Admin -> Firewall SSH Port 22 (Expected: Allowed)
check_pass "[TEST 03] LAN Admin -> Firewall SSH (192.168.100.2 -> :22)" \
    ip netns exec ns-lan-admin nc -zvw2 192.168.100.1 22

# 4. LAN User -> Firewall SSH Port 22 (Expected: Blocked)
check_block "[TEST 04] LAN User  -> Firewall SSH Block (192.168.100.3)" \
    ip netns exec ns-lan-user nc -zvw1 192.168.100.1 22

# 5. EXT Host -> Public Firewall IP:80 DNAT to DMZ Web Server (Expected: Allowed)
check_pass "[TEST 05] EXT Host  -> DMZ Web Server DNAT (192.168.102.1:80)" \
    ip netns exec ns-ext curl -sI --max-time 2 http://192.168.102.1:80

# 6. DMZ Host -> LAN Lateral Movement Attempt (Expected: Blocked)
check_block "[TEST 06] DMZ Host  -> LAN Lateral Movement Block" \
    ip netns exec ns-dmz nc -zvw1 192.168.100.2 22

# 7. EXT Host -> LAN Direct Access Attempt (Expected: Blocked)
check_block "[TEST 07] EXT Host  -> LAN Direct Access Block" \
    ip netns exec ns-ext nc -zvw1 192.168.100.3 80

# 8. LAN User -> EXT Outbound HTTP + SNAT (Expected: Allowed)
check_pass "[TEST 08] LAN User  -> EXT Outbound HTTP + SNAT" \
    ip netns exec ns-lan-user curl -sI --max-time 2 http://192.168.102.2:80

# 9. DMZ Host -> EXT Unauthorized SSH Port 22 (Expected: Blocked)
check_block "[TEST 09] DMZ Host  -> EXT Unauthorized Port Block (:22)" \
    ip netns exec ns-dmz nc -zvw1 192.168.102.2 22

echo "======================================================================"
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo " ALL $PASS_COUNT SECURITY POLICY ASSERTIONS PASSED SUCCESSFULLY"
    echo "======================================================================"
    exit 0
else
    echo " WARNING: $FAIL_COUNT TESTS FAILED ($PASS_COUNT PASSED)"
    echo "======================================================================"
    exit 1
fi

