#!/usr/bin/env bash
# fortress2-ubuntu.sh  –  full stealth VM + dashboard for Ubuntu 22/24
set -euo pipefail
IFS=$'\n\t'
#----------- colours -----------
RED='\e[38;5;196m'; GRN='\e[38;5;82m'; YLW='\e[38;5;214m'; BLU='\e[38;5;39m'; MAG='\e[38;5;201m'; CYN='\e[38;5;51m'; RST='\e[0m'
DARK=${DARK:-0}
if [[ $DARK == 1 ]]; then
  BGD=$'\e[48;5;235m'; FGD=$'\e[38;5;250m'
else
  BGD=$'\e[48;5;255m'; FGD=$'\e[38;5;235m'
fi
#----------- config -----------
VM_NAME="fortress-vm"
VM_DISK=20; VM_RAM=2048; VM_VCPUS=2
CACHE="$HOME/.cache/fortress2"
CFG="$HOME/.fortress2.conf"
LOG="$HOME/fortress2.log"
ASCII_LOGO='
███████████████
█▄─▄▄─█▄─▄─▀█
██─▄▄▄██─▄─██
█▄▄▄▄▄▄▄▄▄▄██
'
#----------- utils -----------
log(){ echo -e "[$(date '+%T')] $*" | tee -a "$LOG"; }
ok(){ log "${GRN}✔${RST} $*"; }
fail(){ log "${RED}✖${RST} $*"; }
warn(){ log "${YLW}⚠${RST} $*"; }
title(){ echo -e "${MAG}${ASCII_LOGO}${RST}\n${CYN}$1${RST}"; }
toggle(){
  local key=$1; local desc=$2; local state=$(grep "^$key=" "$CFG" 2>/dev/null | cut -d= -f2)
  [[ "$state" == "1" ]] && echo -e "${GRN}●${RST} $desc" || echo -e "${RED}○${RST} $desc"
}

#----------- 0.  OS check -----------
grep -Ei 'ubuntu.*2[2-4]' /etc/os-release || { fail "Ubuntu 22/24 required"; exit 1; }

#----------- 1.  deps -----------
sudo apt-get -qq update
sudo apt-get -qq install -y qemu-kvm libvirt-daemon-system virt-manager virtinst ovmf genisoimage nftables macchanger curl jq qemu-utils xvfb nodejs npm v4l2loopback-dkms v4l2loopback-utils ffmpeg cryptsetup boinc-client knot-resolver
sudo usermod -aG libvirt-qemu,kvm,libvirt "$USER"

#----------- 2.  host firewall (nftables) -----------
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
table inet filter {
  set safe  { type inet_service; elements = { 22,53 } }
  chain input  { type filter hook input priority 0; policy drop;
                 ct state established,related accept
                 iif lo accept
                 ip protocol icmp accept
                 ip6 nexthdr ipv6-icmp accept
                 tcp dport @safe accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
sudo systemctl enable --now nftables

#----------- 3.  config file ----------
cat > "$CFG" <<EOF
JA3_ROTATE=1
FONT_CYCLE=1
GPS_STUB=1
WEBCAM_STUB=1
DOH_FAILOVER=1
USB_BACKUP=0
CREDIT_MINER=0
DARK_MODE=0
RES_HOST=127.0.0.1
RES_PORT=1080
EOF

#----------- 4.  cloud image ----------
mkdir -p "$CACHE"
CLOUD_IMG="$CACHE/jammy-server-cloudimg-amd64.img"
QCOW="$CACHE/${VM_NAME}.qcow2"
CLOUD_ISO="$CACHE/${VM_NAME}-cidata.iso"
[ -f "$CLOUD_IMG" ] || curl -L -o "$CLOUD_IMG" https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img
qemu-img create -b "$CLOUD_IMG" -f qcow2 "$QCOW" "${VM_DISK}G"

#----------- 5.  cloud-init ----------
PASS_PLAIN=$(openssl rand -base64 12)
PASS_HASH=$(openssl passwd -6 "$PASS_PLAIN")
SSH_PUB=$(cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "")
mkdir -p /tmp/ci
cat >/tmp/ci/user-data <<EOF
#cloud-config
users:
  - name: fortress
    passwd: $PASS_HASH
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $SSH_PUB
runcmd:
  - systemctl disable multipathd
power_state: { mode: reboot }
EOF
cat >/tmp/ci/meta-data <<EOF
instance-id: $(uuidgen)
local-hostname: $VM_NAME
EOF
genisoimage -quiet -o "$CLOUD_ISO" -V cidata -r -J /tmp/ci/user-data /tmp/ci/meta-data

#----------- 6.  create VM ----------
virt-install --name "$VM_NAME" --memory "$VM_RAM" --vcpus "$VM_VCPUS" \
  --disk "$QCOW,bus=virtio" --disk "$CLOUD_ISO,device=cdrom" \
  --os-variant ubuntu22.04 --network bridge=virbr0,model=virtio \
  --boot uefi --import --noautoconsole --quiet

#----------- 7.  mac randomiser ----------
sudo tee /etc/systemd/system/fortress-mac-randomiser.service >/dev/null <<EOF
[Unit]
Description=Randomise $VM_NAME MAC
After=libvirtd.service
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'virsh dumpxml $VM_NAME | sed -E "s/(<mac address=\")[^\"]*(\")/\1$(openssl rand -hex 6 | sed "s/\(..\)/\1:/g; s/:$//")\2/" | virsh define /dev/stdin'
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable fortress-mac-randomiser.service

#----------- 8.  wait for IP ----------
sleep 15
VM_IP=$(virsh domifaddr "$VM_NAME" | awk 'NR>1{print $4}' | cut -d/ -f1)
[ -n "$VM_IP" ] || { fail "VM IP not found"; exit 1; }

#----------- 9.  push full harden + extras into VM ----------
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /dev/stdin fortress@$VM_IP:'/tmp/fortress-vm-setup.sh' <<'VMEOF'
#!/bin/bash
set -euo pipefail
#----- packages -----
sudo apt-get -qq update
sudo apt-get -qq install -y tor obfs4proxy openvpn nftables dnsmasq curl wget git firefox firejail apparmor-profiles-extra macchanger xvfb nodejs npm v4l2loopback-dkms ffmpeg cryptsetup boinc-client knot-resolver
#----- nftables -----
sudo tee /etc/nftables.conf <<'EOF'
table inet filter {
  set safe { type inet_service; elements = { 80,443,53,9040,9050,1194,51820,19302 } }
  chain input  { type filter hook input priority 0; policy drop;
                 ct state established,related accept
                 iif lo accept
                 ip protocol icmp accept
                 ip6 nexthdr ipv6-icmp accept }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy drop;
                 ct state established,related accept
                 oif lo accept
                 ip daddr 127.0.0.1 tcp dport {9050,9040,8853,19302} accept
                 udp dport 19302 accept
                 udp dport 1194 accept
                 ip saddr 10.0.0.0/8   tcp dport @safe accept
                 ip saddr 172.16.0.0/12 tcp dport @safe accept
                 ip saddr 192.168.0.0/16 tcp dport @safe accept
  }
}
EOF
sudo systemctl enable --now nftables
#----- tor -----
echo -e "AutomapHostsOnResolve 1\nTransPort 127.0.0.1:9040 IsolateClientAddr\nDNSPort 127.0.0.1:8853\nMaxCircuitDirtiness 600" | sudo tee -a /etc/tor/torrc
sudo systemctl restart tor
#----- resolved off -----
sudo systemctl stop systemd-resolved && sudo systemctl disable systemd-resolved
echo nameserver 127.0.0.1 | sudo tee /etc/resolv.conf
#----- ipv6 off -----
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
#----- firefox policy -----
sudo mkdir -p /etc/firefox/policies
echo '{"policies": {"WebRTC": {"Policy": "default_public_and_private_interfaces"}, "DisableTelemetry": true, "NetworkPrediction": false}}' | sudo tee /etc/firefox/policies/policies.json
#----- proxychains -----
echo -e "strict_chain\nproxy_dns\ntcp_read_time_out 8000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5  127.0.0.1 9050\nsocks5  127.0.0.1 1080" | sudo tee /etc/proxychains.conf
#----- cookie-bot -----
mkdir -p ~/cookie-bot
cd ~/cookie-bot
npm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth
#----- dynamic stun -----
sudo tee /usr/local/bin/stun-echo-exitip.sh <<'EOF'
#!/bin/bash
EXIT_IP=$(proxychains -f /etc/proxychains.conf curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || echo "")
[[ "$EXIT_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || { echo "No exit IP"; exit 1; }
cat >/usr/local/bin/fake-stun.py <<PY
import socket, struct
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 19302))
while True:
    data, addr = sock.recvfrom(1024)
    if len(data) < 20: continue
    tid = data[8:20]
    res = b'\x01\x01\x00\x0c' + b'\x00\x00\x00\x00' + tid
    res += b'\x00\x01\x00\x08' + struct.pack('!HH4s', 0x0001, 4, socket.inet_aton('$EXIT_IP'))
    res += b'\x00\x00\x00\x00'
    sock.sendto(res, addr)
PY
chmod +x /usr/local/bin/fake-stun.py
pkill -f fake-stun.py || true
nohup python3 /usr/local/bin/fake-stun.py &
EOF
chmod +x /usr/local/bin/stun-echo-exitip.sh
#----- iptables stun redirect -----
UID=$(id -u fortress)
sudo iptables -t nat -I OUTPUT -m owner --uid-owner $UID -p udp --dport 3478 -j REDIRECT --to-port 19302
sudo netfilter-persistent save
#----- ja3 rotate -----
sudo tee /etc/systemd/system/ja3-rotate.service >/dev/null <<EOF
[Unit]
Description=Rotate JA3
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'FP=(chrome_102 firefox_109 safari_16 ios_16); ln -sf ${FP[RANDOM%4]} /usr/local/bin/active-ja3'
EOF
sudo tee /etc/systemd/system/ja3-rotate.timer >/dev/null <<EOF
[Unit]
Description=Rotate JA3 every 30 min
[Timer]
OnCalendar=*:0/30
Persistent=true
[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now ja3-rotate.timer
#----- font rotate -----
sudo tee /usr/local/bin/font-rotate.sh <<'EOF'
#!/bin/bash
FONT_DIR=/usr/share/fonts/truetype
CACHE=/home/fortress/font-cache
mkdir -p "$CACHE"
fc-list : file | shuf | head -n 200 | xargs -I{} cp {} "$CACHE/"
fc-cache -f "$CACHE"
EOF
chmod +x /usr/local/bin/font-rotate.sh
sudo tee /etc/systemd/system/font-rotate.service >/dev/null <<EOF
[Unit]
Description=Random font subset
After=graphical.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/font-rotate.sh
User=fortress
[Install]
WantedBy=default.target
EOF
sudo systemctl enable font-rotate.service
#----- webcam loopback -----
sudo tee /etc/modules-load.d/v4l2loopback.conf <<< "v4l2loopback"
sudo tee /etc/modprobe.d/v4l2loopback.conf <<< "options v4l2loopback devices=1 video_nr=10 card_label=FortressCam exclusive=0"
sudo modprobe v4l2loopback
ffmpeg -stream_loop -1 -f lavfi -i testsrc=size=1920x1080:rate=30 -f v4l2 /dev/video10 &
#----- doh fail-over -----
sudo tee /etc/knot-resolver/kresd.conf <<EOF
modules.load('policy')
policy.add(policy.FORWARD({'1.1.1.1', '9.9.9.9'}))
cache.size = 100*MB
EOF
sudo systemctl enable --now kresd@kresd.service
echo "nameserver 127.0.2.1" | sudo tee /etc/resolv.conf.secondary
#----- credit miner -----
sudo systemctl disable boinc-client  # off by default – toggle in dashboard
#----- dolphin -----
wget -q https://dolphin-anty.com/api/download?platform=linux64 -O dolphin.AppImage
chmod +x dolphin.AppImage
./dolphin.AppImage --appimage-extract && mv squashfs-root dolphin
#----- gps stub -----
mkdir -p /home/fortress/gps
curl -s https://ipinfo.io/json | jq -r '.loc' > /tmp/loc
read -r lat lon < /tmp/loc
echo "user_pref('geo.provider.network.url', 'data:application/json,{\"location\": {\"lat\": $lat, \"lng\": $lon}, \"accuracy\": 10}');" >> /home/fortress/shop-profile/user.js
VMEOF
ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'bash /tmp/fortress-vm-setup.sh'

#----------- 10.  build dashboard ----------
cat >~/fortress2-tui.sh <<'DASH'
#!/bin/bash
set -euo pipefail
RED='\e[38;5;196m'; GRN='\e[38;5;82m'; YLW='\e[38;5;214m'; BLU='\e[38;5;39m'; MAG='\e[38;5;201m'; CYN='\e[38;5;51m'; RST='\e[0m'
CFG="$HOME/.fortress2.conf"
VM_IP=$(cat ~/.vm_ip 2>/dev/null || echo "192.168.122.100")
RES_HOST=$(grep RES_HOST "$CFG" | cut -d= -f2)
RES_PORT=$(grep RES_PORT "$CFG" | cut -d= -f2)
PROFILE="/home/fortress/shop-profile"

log(){ echo -e "[$(date '+%T')] $*" | tee -a ~/fortress2.log; }
ok(){ log "${GRN}✔${RST} $*"; }
fail(){ log "${RED}✖${RST} $*"; }
head(){
clear
echo -e "${MAG}
███████████████
█▄─▄▄─█▄─▄─▀█
██─▄▄▄██─▄─██
█▄▄▄▄▄▄▄▄▄▄██${RST}  ${CYN}Fortress-2 Dashboard (Ubuntu)${RST}  ${YLW}Proxy: $RES_HOST:$RES_PORT${RST}"
}
toggle(){
  local key=$1; local desc=$2; local state=$(grep "^$key=" "$CFG" 2>/dev/null | cut -d= -f2)
  [[ "$state" == "1" ]] && echo -e "${GRN}●${RST} $desc" || echo -e "${RED}○${RST} $desc"
}
rotate_mac(){
  iface=$(ip route | awk '$1=="default"{print $5; exit}')
  sudo ip link set "$iface" down && sudo macchanger -r "$iface" &>/dev/null && sudo ip link set "$iface" up
  ok "Host MAC rotated"
}
renew_tor(){
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'echo -e "AUTHENTICATE \"\"\\nSIGNAL NEWNYM\\nQUIT" | nc 127.0.0.1 9051 2>/dev/null' && ok "Tor renewed" || fail "Tor renew failed"
}
test_exit(){
  ext=$(ssh -o StrictHostKeyChecking=no fortress@$VM_IP "proxychains -f /etc/proxychains.conf curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || echo TIMEOUT")
  [[ $ext =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && ok "Exit IP: $ext" || fail "Exit IP fail: $ext"
}
test_dns(){
  dns=$(ssh -o StrictHostKeyChecking=no fortress@$VM_IP "proxychains drill -D ipinfo.io 2>/dev/null | grep SERVER | awk '{print \$NF}' || echo TIMEOUT")
  [[ "$dns" == "127.0.0.1" ]] && ok "DNS leak pass" || fail "DNS leak: $dns"
}
test_webrtc(){
  ip=$(ssh -o StrictHostKeyChecking=no fortress@$VM_IP "proxychains curl -s https://browserleaks.com/webrtc 2>/dev/null | grep -oP 'Public IP.*?\K[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1")
  exit_ip=$(proxychains -f /etc/proxychains.conf curl -s https://ipinfo.io/ip 2>/dev/null)
  [[ "$ip" == "$exit_ip" && -n "$ip" ]] && ok "WebRTC matches exit: $ip" || fail "WebRTC mismatch: ${ip:-none}"
}
fp_wizard(){
  echo "===== Fingerprint Wizard ====="
  PS3="OS: "; select OS in "Win11" "Win10" "macOS" "Ubuntu"; do break; done
  PS3="Screen: "; select RES in "1366x768" "1920x1080" "1600x900" "1440x900"; do break; done
  PS3="GPU: "; select GPU in "Intel UHD 620" "AMD Vega 8" "NVIDIA GTX 1650" "Apple M1" "Intel Iris Xe"; do break; done
  PS3="Browser: "; select BR in "Chrome124" "Edge124" "Safari16" "Firefox115"; do break; done
  read -rp "Timezone (e.g. America/New_York): " TZ
  read -rp "Language (e.g. en-US): " LANG
  UA=$(case "$BR" in
    Chrome124) echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";;
    Edge124)   echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0";;
    Safari16)  echo "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15";;
    Firefox115)echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0";;
  esac)
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP "cat >$PROFILE/user.js <<EOF
user_pref('general.useragent.override', '$UA');
user_pref('webgl.renderer-string-override', '$GPU');
user_pref('webgl.vendor-string-override', '$(echo $GPU | awk '{print $1}')');
user_pref('privacy.resistFingerprinting', false);
user_pref('privacy.trackingprotection.enabled', false);
user_pref('media.peerconnection.enabled', true);
user_pref('media.peerconnection.ice.proxy_only', true);
user_pref('media.peerconnection.ice.default_address_only', true);
user_pref('media.peerconnection.ice.no_host', true);
user_pref('intl.accept_languages', '$LANG');
user_pref('intl.locale.requested', '$LANG');
EOF"
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP "sudo timedatectl set-timezone $TZ"
  ok "Fingerprint saved: $BR $RES $GPU $TZ $LANG"
}
warm_cookies(){
  echo -e "${BLU}Warming 30-day live cookie trail…${RST}"
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null /dev/stdin fortress@$VM_IP:~/cookie-bot/warm-history.js <<'EOF'
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());
const PROXY_HOST = process.env.PROXY_HOST || '127.0.0.1';
const PROXY_PORT = process.env.PROXY_PORT || '1080';
const PROFILE  = process.env.PROFILE || '/home/fortress/shop-profile';
const DAYS     = 30;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const human = () => sleep(1000 + Math.random() * 3000);
const pick = arr => arr[Math.floor(Math.random() * arr.length)];
const dateOffset = d => new Date(Date.now() - d * 24 * 60 * 60 * 1000);
const gaps = () => [6, 8, 12, 18, 24, 36, 48].map(h => h * 3600 * 1000);
(async () => {
  const browser = await puppeteer.launch({
    headless: false,
    args: [
      '--no-sandbox',
      `--proxy-server=socks5://${PROXY_HOST}:${PROXY_PORT}`,
      `--user-data-dir=${PROFILE}`,
      '--window-size=1366,768'
    ],
    defaultViewport: { width: 1366, height: 768 }
  });
  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0');
  for (let d = DAYS; d > 0; d--) {
    const day = dateOffset(d);
    await page.evaluateOnNewDocument((ts) => { Date.prototype.getTime = () => ts; }, day.getTime());
    await page.goto('https://amazon.com', { waitUntil: 'networkidle2' }); await human();
    await page.type('#twotabsearchtextbox', pick(['wireless earbuds','gaming mouse','usb-c hub']));
    await page.keyboard.press('Enter'); await page.waitForNavigation({ waitUntil: 'networkidle2' }); await human();
    const products = await page.$$('.s-result-item h2 a');
    if (products.length > 1) { await products[1].click(); await page.waitForNavigation({ waitUntil: 'networkidle2' }); await human();
      const atc = await page.$('#add-to-cart-button'); if (atc) { await atc.click(); await page.waitForResponse(r => r.url().includes('addToCart') && r.status() === 200); }
      await page.goto('about:blank'); }
    await sleep(pick(gaps()));
  }
  for (let d = 15; d > 0; d--) {
    const day = dateOffset(d);
    await page.evaluateOnNewDocument((ts) => { Date.prototype.getTime = () => ts; }, day.getTime());
    await page.goto('https://ebay.com', { waitUntil: 'networkidle2' }); await human();
    await page.type('#gh-ac', 'rtx 4070'); await page.keyboard.press('Enter'); await page.waitForNavigation({ waitUntil: 'networkidle2' }); await human();
    const items = await page.$$('.s-item__title a'); if (items.length) { await items[0].click(); await page.waitForNavigation({ waitUntil: 'networkidle2' }); await human();
      const watch = await page.$('[data-testid="watch-button"]'); if (watch) await watch.click(); }
    await sleep(pick(gaps()));
  }
  await page.goto('https://allbirds.com', { waitUntil: 'networkidle2' }); await human();
  const size = await page.$('[data-size="10"]'); if (size) { await size.click(); await human();
    const atc = await page.$('[data-add-to-cart]'); if (atc) { await atc.click(); await page.waitForResponse(r => r.url().includes('cart/add') && r.status() === 200); } }
  await browser.close();
  console.log('Cookies warmed');
})();
EOF
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'cd ~/cookie-bot && export PROXY_HOST=127.0.0.1 PROXY_PORT=1080 PROFILE=/home/fortress/shop-profile && xvfb-run -a node warm-history.js'
  ok "Cookie trail live"
}
shop_mode(){
  warm_cookies
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'export DISPLAY=:99; pgrep Xvfb || (Xvfb :99 -screen 0 1366x768x24 -ac +extension GLX +render -noreset & sleep 2; fluxbox &); proxychains -f /etc/proxychains.conf sudo -u fortress firefox -profile /home/fortress/shop-profile -no-remote https://amazon.com >/dev/null 2>&1 &'
  ok "Shopping Firefox launched (fingerprint + warm cookies)"
}
dolphin_mode(){
  warm_cookies
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'export DISPLAY=:99; pgrep Xvfb || (Xvfb :99 -screen 0 1366x768x24 -ac +extension GLX +render -noreset & sleep 2; fluxbox &); proxychains -f /etc/proxychains.conf ~/dolphin/dolphin --profile=/home/fortress/dolphin-profile >/dev/null 2>&1 &'
  ok "Dolphin launched with fortress fingerprint + cookies"
}
snapshot(){
  virsh shutdown "$VM_NAME" >/dev/null 2>&1 && sleep 10
  virsh snapshot-create-as "$VM_NAME" "clean-$(date +%s)" --description "auto snapshot" >/dev/null
  virsh start "$VM_NAME" >/dev/null
  ok "VM snapshotted & restarted"
}
revert(){
  snap=$(virsh snapshot-list "$VM_NAME" --name | tail -n1)
  [[ -n "$snap" ]] && { virsh shutdown "$VM_NAME" && sleep 10; virsh snapshot-revert "$VM_NAME" "$snap" --force && virsh start "$VM_NAME"; ok "Reverted to $snap"; } || fail "No snapshot"
}
match_stun(){
  ssh -o StrictHostKeyChecking=no fortress@$VM_IP 'PROXY_HOST=127.0.0.1 PROXY_PORT=1080 bash /usr/local/bin/stun-echo-exitip.sh'
  test_webrtc
}
toggle_set(){
  local key=$1; local new=$2
  sed -i "/^$key=/d" "$CFG"; echo "$key=$new" >> "$CFG"
}
menu_toggle(){
  read -rp "Toggle $1 ? (y/n) " yn
  [[ "$yn" == "y" ]] && toggle_set "$2" $(( 1 - $(grep "^$2=" "$CFG" | cut -d= -f2 || echo 0) ))
}
usb_backup(){
  read -rp "Plug encrypted USB and press enter…"
  sudo cryptsetup luksOpen /dev/disk/by-id/usb-* vault 2>/dev/null || { fail "USB not found"; return; }
  sudo mount /dev/mapper/vault /mnt/vault
  virsh dumpxml fortress-vm > /mnt/vault/fortress.xml
  rsync -a ~/.cache/fortress2/ /mnt/vault/
  virsh snapshot-dumpxml fortress-vm clean > /mnt/vault/snap.xml
  sudo umount /mnt/vault && sudo cryptsetup close vault
  ok "Backup done"
}
credit_miner_toggle(){
  state=$(grep CREDIT_MINER "$CFG" | cut -d= -f2)
  if [[ "$state" == "1" ]]; then
    sudo systemctl stop boinc-client
    toggle_set CREDIT_MINER 0
  else
    sudo systemctl start boinc-client
    toggle_set CREDIT_MINER 1
  fi
}
dark_toggle(){
  DARK=$(( 1 - $(grep DARK_MODE "$CFG" | cut -d= -f2 || echo 0) ))
  toggle_set DARK_MODE $DARK
  export DARK=$DARK
  ok "Dark mode $([[ $DARK == 1 ]] && echo enabled || echo disabled)"
}

#---------- menu ----------
while true; do
head
echo -e "  ${GRN}1${RST}  Rotate host MAC        ${GRN}9${RST}  Fingerprint Wizard"
echo -e "  ${GRN}2${RST}  Renew Tor circuit      ${GRN}0${RST}  Warm Cookie Jar"
echo -e "  ${GRN}3${RST}  Test exit IP           ${GRN}s${RST}  SHOP MODE (Firefox)"
echo -e "  ${GRN}4${RST}  Test DNS leak          ${GRN}d${RST}  SHOP MODE (Dolphin)"
echo -e "  ${GRN}5${RST}  Test WebRTC leak       ${GRN}b${RST}  USB encrypted backup"
echo -e "  ${GRN}6${RST}  Match STUN→exit IP     ${GRN}c${RST}  Credit-miner toggle"
echo -e "  ${GRN}7${RST}  Snapshot VM            ${GRN}t${RST}  Dark-mode toggle"
echo -e "  ${GRN}8${RST}  Revert VM              ${GRN}q${RST}  Quit"
echo -e "\nToggles:"
toggle JA3_ROTATE     "JA3 rotate every 30 min"
toggle FONT_CYCLE     "Font cycle on boot"
toggle GPS_STUB       "GPS lat/lon = exit IP"
toggle WEBCAM_STUB    "Dummy webcam 1080p"
toggle DOH_FAILOVER   "DoH if Tor DNS down"
toggle USB_BACKUP     "Auto USB snapshot"
toggle CREDIT_MINER   "BOINC credit miner"
toggle DARK_MODE      "Dark dashboard theme"
read -rp $'Choice> ' c
case $c in
  1) rotate_mac ;;
  2) renew_tor ;;
  3) test_exit ;;
  4) test_dns ;;
  5) test_webrtc ;;
  6) match_stun ;;
  7) snapshot ;;
  8) revert ;;
  9) fp_wizard ;;
  0) warm_cookies ;;
  s|S) shop_mode ;;
  d|D) dolphin_mode ;;
  b|B) usb_backup ;;
  c|C) credit_miner_toggle ;;
  t|T) dark_toggle ;;
  q|Q) break ;;
  *) fail "Invalid key" ;;
esac
read -rp $'\nPress Enter to continue…'
done
DASH
chmod +x ~/fortress2-tui.sh
echo "$VM_IP" > ~/.vm_ip

#----------- 10.  final banner -----------
title "INSTALL COMPLETE"
echo -e "VM IP      : ${CYN}$VM_IP${RST}"
echo -e "User/Pass  : ${CYN}fortress / $PASS_PLAIN${RST}"
echo -e "Dashboard  : ${CYN}~/fortress2-tui.sh${RST}"
echo -e "Log        : ${CYN}~/fortress2.log${RST}"
echo -e "\nRun ${GRN}~/fortress2-tui.sh${RST} to open the cockpit."
