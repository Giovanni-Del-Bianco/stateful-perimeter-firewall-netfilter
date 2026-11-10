#!/bin/sh
# ==============================================================================
# Multi-Zone Stateful Perimeter Firewall (LAN / DMZ / EXT)
# Course: MSc in Cybersecurity - University of Pisa
# Author: Giovanni Del Bianco
# ==============================================================================

set -e

# 1. Define Interfaces
INTIF="eth0"
DMZIF="eth1"
EXTIF="eth2"

# 2. Define Interface IPv4 Addresses
INTIP="192.168.100.1"
DMZIP="192.168.101.1"
EXTIP="192.168.102.1"

# 3. Define Subnets
INTNET="192.168.100.0/255.255.255.0"
DMZNET="192.168.101.0/255.255.255.0"
EXTNET="192.168.102.0/255.255.255.0"

# 4. Define Specific Hosts
ADMIN="192.168.100.2"
webserver="192.168.101.2"

echo "[INFO] Applying Linux Kernel IPv4 sysctl security parameters..."

# Enable IP forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

# Do not reply to broadcast pings (Smurf attack protection)
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Enable protection from bogus ICMP error messages
echo "1" > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Do not accept ICMP redirects (routing table protection)
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects

# Enable anti-spoofing Reverse Path Filtering
echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter

# Log Martian packets (spoofed/impossible source addresses)
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians

# Load Netfilter kernel modules (ignore errors if built-in)
modprobe ip_tables 2>/dev/null || true
modprobe iptable_nat 2>/dev/null || true
modprobe ip_conntrack 2>/dev/null || true
modprobe ipt_MASQUERADE 2>/dev/null || true

echo "[INFO] Flushing existing rules and resetting counters..."

# Reset rules and counters across filter, mangle, and nat tables
iptables -t filter -F
iptables -t filter -X
iptables -t filter -Z

iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z

iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z

echo "[INFO] Setting Default-Deny policies on filter table..."

# Set Default Policies
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -t nat -P POSTROUTING ACCEPT
iptables -t nat -P PREROUTING ACCEPT
iptables -t nat -P OUTPUT ACCEPT

iptables -t mangle -P OUTPUT ACCEPT
iptables -t mangle -P INPUT ACCEPT
iptables -t mangle -P FORWARD ACCEPT
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT

# Enable loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "[INFO] Configuring INPUT/OUTPUT rules for the Firewall gateway..."

## INPUT Chain
# SSH access to the firewall strictly from the Administrator workstation in LAN
iptables -A INPUT -s $ADMIN -i $INTIF -p tcp --dport 22 -j ACCEPT

# Accept traffic related to already established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Enable ICMP (e.g., ping) towards the firewall from LAN and DMZ
iptables -A INPUT -p icmp -i $DMZIF -j ACCEPT
iptables -A INPUT -p icmp -i $INTIF -j ACCEPT

## OUTPUT Chain
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

## LOCAL LAN NATTING (SNAT)
iptables -t nat -A POSTROUTING -o $EXTIF -s $INTNET -j SNAT --to-source $EXTIP

echo "[INFO] Configuring FORWARD rules (LAN, DMZ, EXT) and DNAT..."

## Traffic from LAN to DMZ and EXT
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 22 -j ACCEPT   # SSH
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 25 -j ACCEPT   # SMTP
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 110 -j ACCEPT  # POP3
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 143 -j ACCEPT  # IMAP2
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 995 -j ACCEPT  # POP3S
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 993 -j ACCEPT  # IMAPS
iptables -A FORWARD -s $INTNET -i $INTIF -p udp --dport 53 -j ACCEPT   # DNS
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 80 -j ACCEPT   # HTTP
iptables -A FORWARD -s $INTNET -i $INTIF -p tcp --dport 443 -j ACCEPT  # HTTPS

# ICMP from LAN and diagnostic replies
iptables -A FORWARD -s $INTNET -i $INTIF -p icmp --icmp-type echo-request -j ACCEPT
iptables -A FORWARD ! -s $INTNET ! -i $INTIF -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A FORWARD ! -s $INTNET ! -i $INTIF -p icmp --icmp-type time-exceeded -j ACCEPT
iptables -A FORWARD ! -s $INTNET ! -i $INTIF -p icmp --icmp-type destination-unreachable -j ACCEPT

## Complete access from Administrator to DMZ and EXT
iptables -A FORWARD -s $ADMIN -j ACCEPT

## Traffic from DMZ to EXT (Split-horizon: never route into INTIF)
iptables -A FORWARD -s $DMZNET -i $DMZIF -d $EXTNET ! -o $INTIF -p tcp --dport 25 -j ACCEPT  # SMTP
iptables -A FORWARD -s $DMZNET -i $DMZIF -d $EXTNET ! -o $INTIF -p udp --dport 53 -j ACCEPT  # DNS
iptables -A FORWARD -s $DMZNET -i $DMZIF -d $EXTNET ! -o $INTIF -p tcp --dport 80 -j ACCEPT  # HTTP
iptables -A FORWARD -s $DMZNET -i $DMZIF -d $EXTNET ! -o $INTIF -p tcp --dport 443 -j ACCEPT # HTTPS

## Traffic from EXT to DMZ (Web Server Port Forwarding via DNAT)
iptables -t nat -A PREROUTING -d $EXTIP -p tcp --dport 80 -j DNAT --to-destination $webserver:80
iptables -A FORWARD -d $webserver -p tcp --dport 80 -j ACCEPT

## Accept traffic of established/related connections across zones
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

## SNAT of DMZ towards EXT
iptables -t nat -A POSTROUTING -o $EXTIF -s $DMZNET -j SNAT --to-source $EXTIP

echo "[INFO] Enabling unicast DROP logging..."

## LOG dropped packets (unicast only)
iptables -A INPUT -m pkttype --pkt-type unicast -j LOG --log-prefix "INPUT DROP: "
iptables -A OUTPUT -m pkttype --pkt-type unicast -j LOG --log-prefix "OUTPUT DROP: "
iptables -A FORWARD -m pkttype --pkt-type unicast -j LOG --log-prefix "FORWARD DROP: "

echo "[SUCCESS] Firewall policy loaded successfully."

