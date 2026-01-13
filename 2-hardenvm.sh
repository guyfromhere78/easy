#!/usr/bin/env bash
# 2-vm-harden.sh  –  inside Ubuntu 22.04 VM: Tor→VPN→Residential chain + nftables kill-switch
set -euo pipefail
RES_HOST="${RES_HOST:-127.0.0.1}"   # residential SOCKS IP
RES_PORT="${RES_PORT:-1080}"        # residential SOCKS port
VPN_CONF="${VPN_CONF:-}"            # /home/pop/my.ovpn (optional)

[ "$EUID" -eq 0 ] || exec sudo bash "$0" "$@"

#---------- 1.  Packages --------------------------------------
apt-get -qq update
apt-get -qq install -y tor obfs4proxy openvpn nftables \
     dnsmasq curl wget git firefox firejail apparmor-profiles-extra

#---------- 2.  Nftables kill-switch --------------------------
cat >/etc/nftables.conf <<'EOF'
table inet filter {
  set safe { type inet_service; elements = { 80, 443, 53, 9040, 9050, 1194, 51820 } }
  chain input  { type filter hook input priority 0; policy drop;
                 ct state established,related accept
                 iif lo accept
                 ip protocol icmp accept
                 ip6 nexthdr ipv6-icmp accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy drop;
                 ct state established,related accept
                 oif lo accept
                 ip daddr 127.0.0.1 tcp dport {9050, 9040, 8853} accept
                 ip daddr 1.1.1.1 tcp dport 853 accept
                 ip6 daddr 2606:4700:4700::1111 tcp dport 853 accept
                 udp dport 1194 accept
                 ip saddr 10.0.0.0/8   tcp dport @safe accept
                 ip saddr 172.16.0.0/12 tcp dport @safe accept
                 ip saddr 192.168.0.0/16 tcp dport @safe accept
  }
}
EOF
systemctl enable --now nftables

#---------- 3.  Tor -------------------------------------------------
cat >>/etc/tor/torrc <<EOF
AutomapHostsOnResolve 1
TransPort 127.0.0.1:9040 IsolateClientAddr
DNSPort 127.0.0.1:8853
MaxCircuitDirtiness 600
EOF
systemctl restart tor

#---------- 4.  DNS leak armour ------------------------------------
systemctl stop systemd-resolved
systemctl disable systemd-resolved
rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" >/etc/resolv.conf

#---------- 5.  IPv6 off -------------------------------------------
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >>/etc/sysctl.conf

#---------- 6.  Firefox policies (WebRTC off, telemetry off) -------
mkdir -p /etc/firefox/policies
cat >/etc/firefox/policies/policies.json <<'EOF'
{"policies": {"DisableFirefoxStudies":true,"DisableTelemetry":true,
             "WebRTC":{"Policy":"DisableNonProxiedUdp"}}}
EOF

#---------- 7.  Optional OpenVPN -----------------------------------
if [[ -n "$VPN_CONF" && -f "$VPN_CONF" ]]; then
   cp "$VPN_CONF" /etc/openvpn/client.conf
   chmod 600 /etc/openvpn/client.conf
   systemctl enable --now openvpn@client
fi

#---------- 8.  Proxychains config (Tor → Residential) -------------
cat >/etc/proxychains.conf <<EOF
strict_chain
proxy_dns
tcp_read_time_out 8000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050
socks5 $RES_HOST $RES_PORT
EOF

#---------- 9.  Final test -----------------------------------------
echo "==========================="
echo "Internal IP (VPN tunnel):"
ip -4 -o addr show scope global
echo -e "\nExit IP (residential):"
proxychains -f /etc/proxychains.conf curl -s https://ipinfo.io/ip
echo -e "\nDNS leak (should be 127.0.0.1):"
proxychains drill -D ipinfo.io | grep SERVER
echo "==========================="
