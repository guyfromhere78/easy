#!/usr/bin/env bash
# 2-vm-harden.sh  –  leak-proof proxy workstation (run INSIDE VM)
set -euo pipefail
############################  CONFIG  ###########################
RES_PROXY_HOST="${RES_PROXY_HOST:-127.0.0.1}"  # residential SOCKS given by provider
RES_PROXY_PORT="${RES_PROXY_PORT:-1080}"
VPN_CONFIG="${VPN_CONFIG:-}"   # path to your .ovpn or .conf
###############################################################

#---------- 0.  Become root if not already -------------------
[ "$EUID" -eq 0 ] || exec sudo bash "$0" "$@"

#---------- 1.  Update & install essentials ------------------
apt -qq update
apt -qq install -y tor obfs4proxy openvpn nftables curl wget \
     git firejail firefox pax-utils apparmor-profiles-extra

#---------- 2.  Lock down firewall (fail-closed) -------------
cat >/etc/nftables.conf <<'EOF'
table inet filter {
  set safe_ports { type inet_service; elements = { 80, 443, 53, 9001, 1194, 51820 } }
  chain input  { type filter hook input priority 0; policy drop;
                 ct state established,related accept
                 iif lo accept
                 ip protocol icmp accept
                 ip6 nexthdr ipv6-icmp accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy drop;
                 ct state established,related accept
                 oif lo accept
                 # Tor entry
                 ip daddr 127.0.0.1 tcp dport 9050 accept
                 # DNS-over-TLS (Cloudflare)
                 ip daddr 1.1.1.1 tcp dport 853 accept
                 ip daddr 2606:4700:4700::1111 tcp dport 853 accept
                 # VPN UDP (edit if you use TCP)
                 udp dport 1194 accept
                 # Safe web ports only AFTER VPN + Tor chains are up
                 ip saddr 10.0.0.0/8   tcp dport @safe_ports accept
                 ip saddr 172.16.0.0/12 tcp dport @safe_ports accept
                 ip saddr 192.168.0.0/16 tcp dport @safe_ports accept
  }
}
EOF
systemctl enable --now nftables

#---------- 3.  Tor – force new circuit every 10 min ---------
cat >>/etc/tor/torrc <<EOF
AutomapHostsOnResolve 1
TransPort 127.0.0.1:9040 IsolateClientAddr
DNSPort 127.0.0.1:8853
MaxCircuitDirtiness 600
EOF
systemctl restart tor

#---------- 4.  DNS leak armour ------------------------------
# a) disable systemd-resolved stub
systemctl stop systemd-resolved
systemctl disable systemd-resolved
rm /etc/resolv.conf
# b) point to Tor DNS
echo "nameserver 127.0.0.1" >/etc/resolv.conf
# c) enforce DNS-over-TLS for clearnet fallback
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/dns-over-tls.conf <<EOF
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com
DNSOverTLS=yes
EOF

#---------- 5.  IPv6 off (prevents WebRTC v6 leaks) ----------
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf

#---------- 6.  Firefox hardening ----------------------------
FIREFOX_PREF="/etc/firefox/policies/policies.json"
mkdir -p "$(dirname "$FIREFOX_PREF")"
cat >"$FIREFOX_PREF" <<EOF
{
  "policies": {
    "DisableFirefoxStudies": true,
    "DisableSystemAddonUpdate": true,
    "DisableTelemetry": true,
    "ExtensionUpdate": false,
    "NetworkPrediction": false,
    "DNSOverHTTPS": { "Enabled": false },
    "WebRTC": { "Policy": "DisableNonProxiedUdp" }
  }
}
EOF

#---------- 7.  VPN launch helper (if config supplied) -------
if [[ -n "$VPN_CONFIG" && -f "$VPN_CONFIG" ]]; then
  # drop root privileges for openvpn
  useradd -m -s /bin/bash vpnuser || true
  cp "$VPN_CONFIG" /etc/openvpn/client.conf
  chown root:root /etc/openvpn/client.conf
  chmod 600 /etc/openvpn/client.conf
  systemctl enable --now openvpn@client
fi

#---------- 8.  Proxychains-NG (Tor → VPN → Residential) -----
cat >/etc/proxychains.conf <<EOF
strict_chain
proxy_dns
tcp_read_time_out 8000
tcp_connect_time_out 8000
[ProxyList]
socks5  127.0.0.1 9050   // tor
socks5  $RES_PROXY_HOST $RES_PROXY_PORT  // residential
EOF

#---------- 9.  App-armor everything -------------------------
aa-enforce /etc/apparmor.d/*openvpn* 2>/dev/null || true
aa-enforce /etc/apparmor.d/*tor*      2>/dev/null || true

#---------- 10.  Final leak test -----------------------------
echo "===  Leak-test  ================================================="
echo -e "\n>>> Internal IP (should be VPN tunnel):"
ip -4 -o addr show scope global | awk '{print $4}'
echo -e "\n>>> Exit IP (should be residential):"
proxychains -f /etc/proxychains.conf curl -s https://ipinfo.io/ip
echo -e "\n>>> DNS leak (should show 127.0.0.1):"
proxychains drill -D ipinfo.io | grep SERVER
echo "================================================================="
