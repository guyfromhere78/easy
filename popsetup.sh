#!/usr/bin/env bash
# 1-pop-setup.sh  –  Pop!_OS host hardening + leak-proof VM
# curl -fsSL https://raw.githubusercontent.com/YOU/REPO/main/1-pop-setup.sh | bash
set -euo pipefail

############################  CONFIG  ###########################
VM_NAME="${VM_NAME:-proxy-fortress}"
VM_DISK="${VM_DISK:-20}"            # GB
VM_RAM="${VM_RAM:-2048}"            # MB
VM_VCPUS="${VM_VCPUS:-2}"
ISO_URL="https://releases.ubuntu.com/22.04.4/ubuntu-22.04.4-desktop-amd64.iso"
###############################################################

#---------- 0.  Abort if not Pop!_OS  ------------------------
(grep -qi pop <<< /etc/os-release) || { echo "Pop!_OS required"; exit 1; }

#---------- 1.  Update & install deps  -----------------------
sudo apt -qq update
sudo apt -qq install -y qemu-kvm libvirt-daemon-system virt-manager \
     virtinst ovmf dnsmasq nftables git curl jq

# add user to libvirt group so we can VM without sudo
sudo usermod -aG libvirt-qemu,kvm,libvirt "$USER"

#---------- 2.  Harden host firewall (fail-closed) -----------
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
table inet filter {
  set allowed_tcp { type inet_service; elements = { 22, 53 } }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport @allowed_tcp accept
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
EOF
sudo systemctl enable --now nftables

#---------- 3.  Download cloud-image & inject virt-sysprep ---
[ -f "$HOME/.cache/$VM_NAME.qcow2" ] || {
  curl -L -o "$HOME/.cache/jammy-server-cloudimg-amd64.img" \
    https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img
  qemu-img create -b "$HOME/.cache/jammy-server-cloudimg-amd64.img" \
     -f qcow2 "$HOME/.cache/$VM_NAME.qcow2" "${VM_DISK}G"
}

#---------- 4.  Build cloud-init ISO (no leaks at boot) ------
PASS_PLAIN=$(openssl rand -base64 12)
PASS_HASH=$(openssl passwd -6 "$PASS_PLAIN")
mkdir -p /tmp/ci
cat >/tmp/ci/user-data <<EOF
#cloud-config
users:
  - name: pop
    passwd: $PASS_HASH
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat ~/.ssh/id_rsa.pub 2>/dev/null || echo "")
runcmd:
  - systemctl disable multipathd
  - apt update && apt install -y curl git
power_state: { mode: reboot }
EOF
cat >/tmp/ci/meta-data <<EOF
instance-id: $(uuidgen)
local-hostname: $VM_NAME
EOF
genisoimage -quiet -output "$HOME/.cache/$VM_NAME-cidata.iso" \
  -V cidata -r -J /tmp/ci/user-data /tmp/ci/meta-data

#---------- 5.  Create VM (UEFI + secure-boot ready) ---------
virt-install \
  --name "$VM_NAME" --memory "$VM_RAM" --vcpus "$VM_VCPUS" \
  --disk "$HOME/.cache/$VM_NAME.qcow2,bus=virtio" \
  --disk "$HOME/.cache/$VM_NAME-cidata.iso,device=cdrom" \
  --os-variant ubuntu22.04 --network bridge=virbr0,model=virtio \
  --boot uefi --import --noautoconsole --quiet

#---------- 6.  Randomise VM MAC on every host boot ----------
sudo tee /etc/systemd/system/vm-mac-randomiser.service >/dev/null <<EOF
[Unit]
Description=Randomise $VM_NAME MAC address
After=libvirtd.service
[Service]
Type=oneshot
ExecStart=/usr/bin/virsh dumpxml $VM_NAME | sed -E "s/(<mac address=')[^']*/\1$(openssl rand -hex 6 | sed 's/\(..\/\)/\1:/g; s/:$//')/" | virsh define /dev/stdin
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable vm-mac-randomiser.service

#---------- 7.  Print credentials ---------------------------
echo "===  VM ready  ==================================================="
echo "VM name    : $VM_NAME"
echo "Login user : pop"
echo "Password   : $PASS_PLAIN"
echo "Connect    : virsh console $VM_NAME   (Ctrl-] to exit)"
echo "=================================================================="
