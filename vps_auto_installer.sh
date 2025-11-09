#!/usr/bin/env bash
# vps-auto-installer.sh
# Full-featured VPS auto installer (Ubuntu 22.04 / Debian 11)
# Features (template):
# - xray (vless/vmess/trojan) with WS+TLS and plain TLS ports
# - WireGuard
# - StrongSwan (IKEv2 MSCHPv2)
# - OpenVPN (easy-rsa)
# - L2TP/IPsec (xl2tpd + strongswan)
# - PPTP (pptpd)
# - OpenSSH, Dropbear
# - Badvpn UDPGW
# - Port checker (TCP/UDP)
# - Support for custom UDP ports and provider notes
# IMPORTANT: Run as root. Provide DOMAIN env var if you want Let's Encrypt TLS.

set -euo pipefail
LANG=C
SCRIPT_NAME=$(basename "$0")
ROOT_UID=0

# ---------- User editable defaults (matches user's requirements) ----------
DOMAIN=""                # set to your domain to enable Let's Encrypt
PROVIDER="DIGITALOCEAN"  # informational only

# Ports requested by user
OPENSSH_PORT=22
DROPBEAR_PORTS=(81 444)
VLESS_TLS_PORT=10002
VLESS_WS_PORT=10004
VMESS_TLS_PORT=10001
VMESS_WS_PORT=10000
V2RAY_TROJAN_PORT=443
OPENVPN_PORTS_TCP=(110 443 992 1194)
PPTP_PORT=1723
L2TP_PORTS=(443 5555)
WIREGUARD_PORT=1024
BADVPN_PORTS=(446 7200)
WS_HOST_PORTS=(2086 8880 2096) # OpenSSH WS(2086), Dropbear WS(8880), SSL WS(2096)
UDP_CUSTOM_MIN=1
UDP_CUSTOM_MAX=65535
SLOWDNS_PUBKEY=""  # if you have a public key for slowDNS

# ---------- Helper functions ----------
echoinfo(){ echo -e "\e[34m[INFO]\e[0m $*"; }
echowarn(){ echo -e "\e[33m[WARN]\e[0m $*"; }
echoerr(){ echo -e "\e[31m[ERR]\e[0m $*" >&2; }

require_root(){ if [[ $(id -u) -ne $ROOT_UID ]]; then echoerr "Run as root!"; exit 1; fi }

detect_os(){
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
  else
    echoerr "Unsupported OS"; exit 1
  fi
  if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
    echowarn "This script targets Ubuntu/Debian. Continue at your own risk."
  fi
}

apt_update(){
  echoinfo "Updating package lists..."
  apt-get update -y
  apt-get upgrade -y
}

install_packages(){
  echoinfo "Installing required packages..."
  apt-get install -y curl wget socat unzip net-tools iproute2 iptables iptables-persistent \
    software-properties-common ca-certificates gnupg lsb-release dialog build-essential \
    bash-completion openvpn easy-rsa strongswan xl2tpd pptpd hostapd dnsutils ncurses-term \
    iptables-persistent netcat-openbsd qrencode
}

open_port_ufw(){
  if command -v ufw >/dev/null 2>&1; then
    echoinfo "Configuring UFW (if present)..."
    ufw allow $1 >/dev/null 2>&1 || true
  fi
}

# ---------- TLS: acme.sh (Let's Encrypt) ----------
install_acme(){
  if [[ -z "$DOMAIN" ]]; then
    echowarn "No DOMAIN set. TLS via Let's Encrypt will be skipped; self-signed certs used instead."
    return
  fi
  echoinfo "Installing acme.sh and issue cert for $DOMAIN..."
  curl -sSfLo /root/acme-install.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh || true
  if [[ -f /root/acme-install.sh ]]; then
    bash /root/acme-install.sh --install --nocron >/dev/null 2>&1 || true
    export PATH="$HOME/.acme.sh:$PATH"
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --force || echowarn "acme.sh failed to issue cert"
  fi
}

# ---------- xray (v2ray) install & config ----------
install_xray(){
  echoinfo "Installing xray-core (V2Ray)..."
  bash -c "$(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)" || echowarn "xray auto installer failed; attempting manual"
  # create a minimal xray config with VLESS+VMESS+Trojan listeners
  mkdir -p /etc/xray
  UUID1=$(cat /proc/sys/kernel/random/uuid)
  UUID2=$(cat /proc/sys/kernel/random/uuid)
  cat >/etc/xray/config.json <<EOF
{
  "log": {"access":"/var/log/xray-access.log","error":"/var/log/xray-error.log","loglevel":"warning"},
  "inbounds":[
    {"port":$VLESS_TLS_PORT, "protocol":"vless","settings":{"clients":[{"id":"$UUID1"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}}},
    {"port":$VLESS_WS_PORT, "protocol":"vless","settings":{"clients":[{"id":"$UUID2"}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vless"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}}},
    {"port":$VMESS_TLS_PORT, "protocol":"vmess","settings":{"clients":[{"id":"$UUID1","alterId":0}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}}},
    {"port":$VMESS_WS_PORT, "protocol":"vmess","settings":{"clients":[{"id":"$UUID2","alterId":0}]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vmess"},"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}}},
    {"port":$V2RAY_TROJAN_PORT, "protocol":"trojan","settings":{"clients":[{"password":"trojan-password"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/xray/xray.crt","keyFile":"/etc/xray/xray.key"}]}}}
  ],
  "outbounds":[{"protocol":"freedom","settings":{}}]
}
EOF
  # TLS certs
  if [[ -n "$DOMAIN" && -f "$HOME/.acme.sh/${DOMAIN}/${DOMAIN}.cer" ]]; then
    mkdir -p /etc/xray
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
      --key-file /etc/xray/xray.key \
      --fullchain-file /etc/xray/xray.crt --reloadcmd "systemctl restart xray.service" || echowarn "install-cert failed"
  else
    echowarn "Using self-signed certificate for xray"
    openssl req -x509 -nodes -days 3650 -subj "/CN=$DOMAIN" -newkey rsa:2048 -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
  fi
  systemctl enable xray || true
  systemctl restart xray || true
  echoinfo "xray installed. VLESS UUIDs: $UUID1, $UUID2 (keep them secret)"
}

# ---------- WireGuard ----------
install_wireguard(){
  echoinfo "Installing WireGuard..."
  apt-get install -y wireguard qrencode
  WG_PRIV_KEY=$(wg genkey)
  WG_PUB_KEY=$(echo "$WG_PRIV_KEY" | wg pubkey)
  mkdir -p /etc/wireguard
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $WG_PRIV_KEY
Address = 10.0.0.1/24
ListenPort = $WIREGUARD_PORT
SaveConfig = true
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0
  systemctl start wg-quick@wg0 || echowarn "Failed to start WireGuard"
  echoinfo "WireGuard installed on port $WIREGUARD_PORT (server public key: $WG_PUB_KEY)"
}

# ---------- StrongSwan (IKEv2) ----------
install_ikev2(){
  echoinfo "Installing StrongSwan (IKEv2) for IKEv2 EAP-MSCHAPv2..."
  apt-get install -y strongswan strongswan-pki libstrongswan-extra-plugins
  # Minimal sample config (user must add username/password to /etc/ipsec.secrets)
  cat >/etc/ipsec.conf <<'EOF'
config setup
  uniqueids=never

conn ikev2-vpn
  auto=add
  compress=no
  type=tunnel
  fragmentation=yes
  forceencaps=yes
  dpdaction=clear
  dpddelay=300s
  rekey=no
  left=%any
  leftid=@server
  leftcert=serverCert.pem
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  rightsourceip=10.10.10.0/24
  rightsendcert=never
  eap_identity=%identity
EOF
  systemctl restart strongswan || true
  echoinfo "StrongSwan installed. Add users in /etc/ipsec.secrets and a proper cert for production."
}

# ---------- OpenVPN ----------
install_openvpn(){
  echoinfo "Installing OpenVPN (easy-rsa)..."
  apt-get install -y openvpn easy-rsa
  make-cadir /etc/openvpn/easy-rsa
  # This script won't build full PKI here to keep things compact. Provide starter commands.
  echowarn "OpenVPN installed. You must initialize PKI and generate server/client certs (see /etc/openvpn/easy-rsa)."
}

# ---------- L2TP/IPsec & PPTP ----------
install_l2tp_pptp(){
  echoinfo "Installing L2TP/IPsec (xl2tpd + strongswan) and PPTP..."
  apt-get install -y xl2tpd strongswan pptpd
  systemctl enable xl2tpd pptpd
  echoinfo "L2TP and PPTP packages installed. Configure /etc/ppp/ and /etc/ipsec.conf for production."
}

# ---------- OpenSSH & Dropbear ----------
install_ssh_dropbear(){
  echoinfo "Ensuring OpenSSH is installed and configuring Dropbear..."
  apt-get install -y openssh-server dropbear
  sed -i "s/#Port 22/Port $OPENSSH_PORT/" /etc/ssh/sshd_config || true
  systemctl restart sshd || true
  # configure dropbear ports
  for p in "${DROPBEAR_PORTS[@]}"; do
    echoinfo "Allowing Dropbear port $p"
  done
  # update /etc/default/dropbear
  sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=81/' /etc/default/dropbear || true
  # Additional ports via systemd override
  systemctl enable dropbear
  systemctl restart dropbear || true
}

# ---------- BadVPN UDPGW ----------
install_badvpn(){
  echoinfo "Installing BADVPN UDPGW..."
  apt-get install -y cmake git build-essential
  cd /tmp
  if [[ ! -d badvpn ]]; then
    git clone https://github.com/ambrop72/badvpn.git
  fi
  cd badvpn
  mkdir -p build && cd build
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
  make -j2
  cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw || true
  for p in "${BADVPN_PORTS[@]}"; do
    nohup /usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:$p >/var/log/badvpn-$p.log 2>&1 &
  done
}

# ---------- Port Checker ----------
port_checker(){
  # Usage: port_checker host port[,port2,...]
  local host="$1"
  local ports_raw="$2"
  IFS=',' read -ra ports <<<"$ports_raw"
  echoinfo "Checking ports on $host: ${ports[*]}"
  for p in "${ports[@]}"; do
    # Try TCP
    if nc -z -w3 "$host" "$p" >/dev/null 2>&1; then
      echo "$p/tcp => OPEN"
    else
      echo "$p/tcp => CLOSED or FILTERED"
    fi
    # UDP check (best-effort): send empty packet and wait for ICMP or no response
    timeout 2 bash -c "echo >/dev/udp/$host/$p" 2>/dev/null || echo "$p/udp => no-response or filtered"
  done
}

# ---------- SlowDNS placeholder ----------
install_slowdns(){
  echoinfo "SlowDNS: this script creates a placeholder. SlowDNS setups are provider-specific."
  if [[ -n "$SLOWDNS_PUBKEY" ]]; then
    echoinfo "You provided a SlowDNS public key; implement client/server accordingly."
  else
    echowarn "No SlowDNS public key provided. Please configure SlowDNS manually if needed."
  fi
}

# ---------- Main ----------
main(){
  require_root
  detect_os
  apt_update
  install_packages
  install_acme
  install_xray
  install_wireguard
  install_ikev2
  install_openvpn
  install_l2tp_pptp
  install_ssh_dropbear
  install_badvpn
  install_slowdns

  echoinfo "--- SUMMARY ---"
  echoinfo "xray VLESS TLS: $VLESS_TLS_PORT"
  echoinfo "xray VLESS WS:  $VLESS_WS_PORT"
  echoinfo "xray VMESS TLS: $VMESS_TLS_PORT"
  echoinfo "xray VMESS WS:  $VMESS_WS_PORT"
  echoinfo "Trojan (xray): $V2RAY_TROJAN_PORT"
  echoinfo "WireGuard port: $WIREGUARD_PORT"
  echoinfo "OpenVPN ports: ${OPENVPN_PORTS_TCP[*]}"
  echoinfo "PPTP port: $PPTP_PORT"
  echoinfo "BADVPN ports: ${BADVPN_PORTS[*]}"
  echoinfo "If you want to run port checks, call: $SCRIPT_NAME --check host port[,port2,...]"
  echoinfo "Note: This script is a template and requires manual verification and hardening before production use."
}

# ---------- CLI ----------
if [[ ${1:-} == "--check" ]]; then
  if [[ -z ${2:-} || -z ${3:-} ]]; then
    echo "Usage: $SCRIPT_NAME --check <host> <port[,port2,...]>"; exit 1
  fi
  port_checker "$2" "$3"
  exit 0
fi

main "$@"
