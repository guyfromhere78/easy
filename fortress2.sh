#!/usr/bin/env bash
# fortress2.sh  –  full-featured stealth VM + polished dashboard
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
box(){ echo -e "${BLU}┌─ $1${RST}"; }
toggle(){
  local key=$1; local desc=$2; local state=$(grep "^$key=" "$CFG" 2>/dev/null | cut -d= -f2)
  [[ "$state" == "1" ]] && echo -e "${GRN}●${RST} $desc" || echo -e "${RED}○${RST} $desc"
}

#----------- 0.  OS check -----------
grep -qi pop <<< /etc/os-release || { fail "Pop!_OS required"; exit 1; }

#----------- 1.  deps -----------
sudo apt-get -qq update
sudo apt-get -qq install -y qemu-kvm libvirt-daemon-system virtinst ovmf genisoimage nftables macchanger curl jq qemu-utils xvfb nodejs npm v4l2loopback-dkms v4l2loopback-utils ffmpeg cryptsetup boinc-client knot-resolver
sudo usermod -aG libvirt-qemu,kvm,libvirt "$USER"

#----------- 2.  host firewall -----------
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
After=graphical
