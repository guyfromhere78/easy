#!/usr/bin/env bash
# leak-cockpit.sh  –  terminal UI for anti-detect browser + proxy leak checks
set -euo pipefail
GREEN='\e[1;32m'; RED='\e[1;31m'; YELLOW='\e[1;33m'; NC='\e[0m'
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"   # SOCKS5 IP
PROXY_PORT="${PROXY_PORT:-1080}"        # SOCKS5 port
BROWSER="${BROWSER:-multilogin}"        # multilogin | kameleo | adspower | dolphin | gologin

#---------- helpers ------------------------------------------
ok()  { echo -e "${GREEN}✓${NC} $*"; }
fail(){ echo -e "${RED}✗${NC} $*"; }
warn(){ echo -e "${YELLOW}⚠${NC} $*"; }
pause(){ read -rp "Press Enter to continue…"; }

menu_header(){
  clear
  cat <<EOF
╔══════════════════════════════════════════════════════════════╗
║         ANTI-DETECT BROWSER  –  LEAK-PROOF COCKPIT         ║
╚══════════════════════════════════════════════════════════════╝
Proxy: $PROXY_HOST:$PROXY_PORT   Browser: $BROWSER
----------------------------------------------------------------
EOF
}

rotate_mac(){
  sudo ip link set dev "$(ip route | awk '$1=="default"{print $5; exit}')" down
  sudo macchanger -r "$(ip route | awk '$1=="default"{print $5; exit}')" >/dev/null
  sudo ip link set dev "$(ip route | awk '$1=="default"{print $5; exit}')" up
  ok "MAC rotated"
}

flush_dns(){
  sudo systemd-resolve --flush-caches 2>/dev/null || sudo resolvectl flush-caches
  ok "DNS cache flushed"
}

test_proxy(){
  local extip
  extip=$(socksify curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || echo "TIMEOUT")
  if [[ "$extip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
     ok "Proxy OK – exit IP $extip"
  else
     fail "Proxy unreachable or timeout"
  fi
}

test_dns_leak(){
  local dnsip
  dnsip=$(socksify drill -D ipinfo.io 2>/dev/null | grep SERVER | awk '{print $NF}')
  if [[ "$dnsip" == "127.0.0.1" ]]; then
     ok "DNS leak test pass (127.0.0.1)"
  else
     fail "DNS leak – resolver $dnsip"
  fi
}

test_webrtc(){
  firefox --new-instance --profile /tmp/ff-webrtc-test \
     -url "https://browserleaks.com/webrtc" 2>/dev/null &
  warn "Manual check – WebRTC section must show NO usable IP"
}

update_browser(){
  case "$BROWSER" in
    multilogin) sudo snap refresh multilogin || true ;;
    kameleo)  wget -q https://kameleo.io/latest-deb -O /tmp/kameleo.deb && sudo dpkg -i /tmp/kameleo.deb ;;
    adspower) bash <(curl -fsSL https://dlp.adspower.net/linux/install) ;;
    dolphin)  bash <(curl -fsSL https://dolphin-anty.com/linux/install) ;;
    gologin)  wget -q https://gologin.com/api/download?platform=linux64 -O /tmp/gologin.AppImage && chmod +x /tmp/gologin.AppImage ;;
  esac
  ok "$BROWSER updated / installed"
}

launch_profile(){
  local profdir
  profdir="$HOME/profiles/antidetect-$(date +%s)"
  mkdir -p "$profdir"
  case "$BROWSER" in
    multilogin)  snap run multilogin --profile-path="$profdir" --proxy-type=socks5 --proxy-host="$PROXY_HOST" --proxy-port="$PROXY_PORT" ;;
    kameleo)     kameleo-cli create-profile --proxy-server "$PROXY_HOST:$PROXY_PORT" --proxy-type socks5 --path "$profdir" && kameleo-cli launch "$profdir" ;;
    adspower)    adspower --proxy-type=socks5 --proxy-host="$PROXY_HOST" --proxy-port="$PROXY_PORT" --profile-dir="$profdir" ;;
    dolphin)     dolphin --proxy-type=socks5 --proxy-host="$PROXY_HOST" --proxy-port="$PROXY_PORT" --user-data-dir="$profdir" ;;
    gologin)     /tmp/gologin.AppImage --proxy-server="socks5://$PROXY_HOST:$PROXY_PORT" --user-data-dir="$profdir" ;;
  esac
}

#---------- menu loop ----------------------------------------
while true; do
  menu_header
  cat <<EOF
 1) Rotate host MAC address
 2) Flush DNS cache
 3) Test proxy (exit IP)
 4) Test DNS leak
 5) Test WebRTC leak (opens Firefox)
 6) Update / install browser core
 7) Launch NEW hardened profile
 8) Edit proxy host:port
 9) Show checklist (printable)
 0) Exit
EOF
  read -rp "Select> " choice
  case "$choice" in
    1) rotate_mac; pause ;;
    2) flush_dns; pause ;;
    3) test_proxy; pause ;;
    4) test_dns_leak; pause ;;
    5) test_webrtc; pause ;;
    6) update_browser; pause ;;
    7) launch_profile; pause ;;
    8) read -rp "New SOCKS5 host: " PROXY_HOST; read -rp "New SOCKS5 port: " PROXY_PORT ;;
    9) less <<< "$(curl -fsSL https://raw.githubusercontent.com/jetbrains/ignore/master/checklist.md 2>/dev/null || cat <<'EOF'
=== ANTI-DETECT CHECK-LIST ===
 1. Host firewall active (nftables)
 2. VM / container running
 3. MAC rotated
 4. DNS = 127.0.0.1
 5. WebRTC disabled
 6. IPv6 disabled
 7. SOCKS5 proxy set & tested
 8. Browser core updated
 9. Canvas/WebGL noise ON
10. TZ & language match proxy
11. GPS override set
12. WebGL vendor string spoofed
13. DNS leak = proxy IP
14. WebRTC leak = none
15. Pre-paid card + burner email
================================
EOF
)" ;;
    0) break ;;
    *) warn "Invalid choice" ;;
  esac
done
