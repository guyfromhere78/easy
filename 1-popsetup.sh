#!/usr/bin/env bash
# 1-pop-setup.sh  –  Pop!_OS 22/24 host: KVM VM + MAC randomiser + nftables
set -euo pipefail
VM_NAME="proxy-fortress"
VM_DISK=20   # GB
VM_RAM=2048  # MB
VM_VCPUS=2

#---------- 0.  Pop!_OS check --------------------------------
grep -qi pop <<< /etc/os-release || { echo "This script is written for Pop!_OS only"; exit 1; }

#---------- 1.  Install deps ----------------------------------
sudo apt-get -qq update
sudo apt-get -qq install -y qemu-kvm libvirt-daemon-system virt-manager \
                            virtinst ovmf dnsmasq nftables qemu-utils

sudo usermod -aG libvirt-qemu,kvm,libvirt "$USER"

#---------- 2.  Host firewall (fail-closed) -------------------
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
table inet filter {
  set safe { type inet_service; elements = { 22, 53 } }
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport @safe accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
EOF
sudo systemctl enable --now nftables

#---------- 3.  Download Ubuntu 22.04 cloud image -------------
CLOUD_IMG="$HOME/.cache/jammy-server-cloudimg-amd64.img"
[ -f "$CLOUD_IMG" ] || {
  mkdir -p "$HOME/.cache"
  wget -q --show-progress -O "$CLOUD_IMG" \
    https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img
}
QCOW="$HOME/.cache/$VM_NAME.qcow2"
qemu-img create -b "$CLOUD_IMG" -f qcow2 "$QCOW" "${VM_DISK}G"

#---------- 4.  Cloud-init ISO (no leaks at first boot) -------
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
power_state:
  mode: reboot
EOF
cat >/tmp/ci/meta-data <<EOF
instance-id: $(uuidgen)
local-hostname: $VM_NAME
EOF
genisoimage -quiet -o "$HOME/.cache/$VM_NAME-cidata.iso" \
  -V cidata -r -J /tmp/ci/user-data /tmp/ci/meta-data

#---------- 5.  Create VM -------------------------------------
virt-install \
  --name "$VM_NAME" --memory "$VM_RAM" --vcpus "$VM_VCPUS" \
  --disk "$QCOW,bus=virtio" \
  --disk "$HOME/.cache/$VM_NAME-cidata.iso,device=cdrom" \
  --os-variant ubuntu22.04 --network bridge=virbr0,model=virtio \
  --boot uefi --import --noautoconsole --quiet

#---------- 6.  Randomise MAC on every host reboot ------------
sudo tee /etc/systemd/system/vm-mac-randomiser.service >/dev/null <<EOF
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
sudo systemctl enable vm-mac-randomiser.service

#---------- 7.  Done ------------------------------------------
echo "=============================================="
echo "VM created : $VM_NAME"
echo "user/pass  : pop / $PASS_PLAIN"
echo "Connect    : virsh console $VM_NAME"
echo "=============================================="
