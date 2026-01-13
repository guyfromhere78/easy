#!/bin/bash
set -e
user=${SUDO_USER:-ml}          # unprivileged account that will run the browser

# 2.1  Dependencies
apt update && apt install -y git golang-go unzip cmake build-essential \
  libnss3 libatk1.0-0 libatk-bridge2.0-0 libxcomposite1 libxdamage1 \
  libxrandr2 libgbm1 libpango-1.0-0 libpangocairo-1.0-0 libasound2 \
  fonts-liberation fonts-noto-color-emoji

# 2.2  utls + ja3-spoofer (forces Windows JA3)
go install github.com/refraction-networking/utls/ja3transport@latest
sudo cp ~/go/bin/ja3transport /usr/local/bin/

# 2.3  Camoufox (pre-built anti-detect chromium)
wget -q https://github.com/camoufox/camoufox/releases/latest/download/camoufox-linux-x86_64.zip
unzip -q camoufox-linux-x86_64.zip -d /opt/
chmod +x /opt/camoufox/camoufox
ln -s /opt/camoufox/camoufox /usr/local/bin/camoufox
rm camoufox-linux-x86_64.zip

# 2.4  Create launcher wrapper with frozen fingerprint
cat >/usr/local/bin/shopfox <<'SHOP'
#!/bin/bash
export MOZ_ACCELERATED=1
export DISPLAY_SIZE="1536x864"
export TZ="America/New_York"

# Camoufox flags that match the baseline
exec camoufox \
  --window-size=1536,864 \
  --force-device-scale-factor=1.25 \
  --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.105 Safari/537.36" \
  --platform="Windows" \
  --gpu="ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0)" \
  --cores=4 \
  --memory=8 \
  --timezone-id=America/New_York \
  --locale=en-US \
  --webrtc-ip-handling-policy=default_public_interface_only \
  --disable-features=TranslateUI,BackForwardCache,InterestFeedContentSuggestions \
  --enable-features=NetworkService,NetworkServiceInProcess \
  --ja3=fake_windows_chrome119 \
  "$@"
SHOP
chmod +x /usr/local/bin/shopfox
chown $user:$user /usr/local/bin/shopfox

# 2.5  AppArmor silence (optional)
aa-complain /opt/camoufox/camoufox 2>/dev/null || true

echo "Retail-stealth browser ready.  Run:  shopfox"
