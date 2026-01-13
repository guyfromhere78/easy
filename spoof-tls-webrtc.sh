#!/usr/bin/env bash
# spoof-tls-webrtc.sh  –  spoof TLS fingerprint + disable WebRTC (run INSIDE VM)
set -euo pipefail
GREEN='\e[32m'; RED='\e[31m'; NC='\e[0m'
check(){ echo -e "${GREEN}✓${NC} $*"; }
die(){ echo -e "${RED}✗${NC} $*" >&2; exit 1; }

# ---------- 0.  OS check ------------------------------------
command -v apt >/dev/null || die "Debian-based OS required"

# ---------- 1.  Install deps --------------------------------
sudo apt-get -qq update
sudo apt-get -qq install -y curl ca-certificates xz-utils \
                            unzip jq iptables-persistent

# ---------- 2.  Install tls-client (utls) -------------------
TLS_VER=$(curl -s https://api.github.com/repos/ameshkov/tls-client/releases/latest | jq -r .tag_name)
TLS_BIN="$HOME/.local/bin/tls-client"
mkdir -p "$HOME/.local/bin"
curl -fsSL "https://github.com/ameshkov/tls-client/releases/download/${TLS_VER}/tls-client-linux-amd64-${TLS_VER}.tar.xz" \
  | tar -xJ -C /tmp
mv /tmp/tls-client-linux-amd64 "$TLS_BIN"
chmod +x "$TLS_BIN"
check "utls (tls-client) installed → $TLS_BIN"

# ---------- 3.  Install cycletls (static node binary) -------
CYCLE_VER=$(curl -s https://api.github.com/repos/Danny-Dasilva/CycleTLS/releases/latest | jq -r .tag_name)
CYCLE_BIN="$HOME/.local/bin/cycletls"
curl -fsSL "https://github.com/Danny-Dasilva/CycleTLS/releases/download/${CYCLE_VER}/cycletls-linux-amd64-${CYCLE_VER}.tar.xz" \
  | tar -xJ -C /tmp
mv /tmp/cycletls-linux-amd64 "$CYCLE_BIN"
chmod +x "$CYCLE_BIN"
check "cycletls installed → $CYCLE_BIN"

# ---------- 4.  Create handy spoof wrappers -----------------
for fp in chrome_102 firefox_109 safari_16 ios_16; do
cat > "$HOME/.local/bin/$fp" <<EOF
#!/bin/bash
# Spoof TLS fingerprint: $fp
exec tls-client -fp $fp -proxy socks5://\$PROXY_HOST:\$PROXY_PORT "\$@"
EOF
chmod +x "$HOME/.local/bin/$fp"
done
check "CLI wrappers created: chrome_102, firefox_109, safari_16, ios_16"

# ---------- 5.  Browser-policy WebRTC disable (all users) ---
# Chromium / Brave / Edge policy
POL_DIR="/etc/chromium/policies/managed"
sudo mkdir -p "$POL_DIR"
echo '{"WebRtcUdpPortRange": {}, "WebRtcIPHandlingPolicy": "disable_non_proxied_udp"}' \
  | sudo tee "$POL_DIR/webrtc.json" >/dev/null

# Firefox policy
FIREFOX_POL="/etc/firefox/policies/policies.json"
sudo mkdir -p "$(dirname "$FIREFOX_POL")"
cat <<EOF | sudo tee "$FIREFOX_POL" >/dev/null
{"policies": {"WebRTC": {"Policy": "DisableNonProxiedUdp"},
              "DisableTelemetry": true,
              "NetworkPrediction": false}}
EOF
check "WebRTC disabled via browser policy"

# ---------- 6.  OS-level WebRTC guard (iptables) ------------
# block UDP 3478-3497 (STUN) + 49152-65535 (WebRTC media)
sudo iptables -I OUTPUT -p udp --dport 3478:3497 -j DROP
sudo iptables -I OUTPUT -p udp --dport 49152:65535 -j DROP
sudo ip6tables -I OUTPUT -p udp --dport 3478:3497 -j DROP
sudo ip6tables -I OUTPUT -p udp --dport 49152:65535 -j DROP
sudo netfilter-persistent save
check "OS-level WebRTC UDP ports blocked"

# ---------- 7.  Fail-closed kill-switch for spoof tunnel ----
# if tls-client exits, nothing leaves the box
sudo iptables -I OUTPUT -m owner --uid-owner "$(id -u)" -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN \
  -j DROP
# remove the rule when tls-client is running (wrapper handles)
cat >> "$HOME/.local/bin/spoof-surf" <<'EOF'
#!/bin/bash
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-1080}"
FP="${1:-chrome_102}"
shift
# lift SYN block while we tunnel
sudo iptables -D OUTPUT -m owner --uid-owner "$(id -u)" -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP 2>/dev/null || true
tls-client -fp "$FP" -proxy "socks5://$PROXY_HOST:$PROXY_PORT" "$@"
# restore block on exit
sudo iptables -I OUTPUT -m owner --uid-owner "$(id -u)" -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j DROP
EOF
chmod +x "$HOME/.local/bin/spoof-surf"
check "Fail-closed wrapper created → spoof-surf [chrome_102|firefox_109|safari_16|ios_16]"

# ---------- 8.  Quick test ----------------------------------
echo
check "Running spoof test (chrome_102 fingerprint)..."
spoof-surf chrome_102 https://ja3er.com/json 2>/dev/null | jq .
echo
echo -e "${GREEN}All done.${NC}  Usage examples:"
echo "  spoof-surf chrome_102  https://ipinfo.io"
echo "  firefox_109  https://browserleaks.com/webrtc   (WebRTC should show NO IP)"
