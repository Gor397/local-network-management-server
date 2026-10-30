#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/.."
if [ "$#" -lt 1 ]; then echo 'Usage: sudo scripts/bootstrap.sh LAN_IP [DNS_NAME]'; exit 2; fi
lantern_ip=$1
lantern_dns=${2:-management.local}
case "$lantern_ip" in *[!0-9.]*) echo 'A literal IPv4 LAN address is required'; exit 2;; esac
case "$lantern_dns" in *[!a-zA-Z0-9.-]*) echo 'Invalid DNS name'; exit 2;; esac
# Router management subnets. Default: the /24 around LAN_IP. Override for other or multiple subnets.
lantern_router_networks=${ROUTER_NETWORKS:-$(echo "$lantern_ip" | cut -d. -f1-3).0/24}
case "$lantern_router_networks" in *[!0-9./,]*) echo 'Invalid ROUTER_NETWORKS'; exit 2;; esac
if [ "$(id -u)" != 0 ]; then echo 'Run as root to set container volume ownership (UID 10001 and GID 101).'; exit 2; fi
mkdir -p data/keys data/trust data/tls data/repository data/recordings
if [ ! -f .env ]; then
  lantern_db_password=$(openssl rand -hex 32)
  lantern_encryption=$(openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n')
  cat > .env <<EOF
POSTGRES_USER=lantern
POSTGRES_DB=lantern
POSTGRES_PASSWORD=$lantern_db_password
DATABASE_URL=postgresql+psycopg://lantern:$lantern_db_password@db/lantern
ENCRYPTION_KEY=$lantern_encryption
DATA_DIR=/data
PUBLIC_ORIGIN=https://$lantern_ip
TRUSTED_HOSTS=$lantern_ip,$lantern_dns,localhost,127.0.0.1
LAN_BIND_IP=$lantern_ip
HTTPS_PORT=443
COOKIE_SECURE=true
LOW_RESOURCE_MODE=true
OPERATION_MODE=read_only
TEST_ROUTERS=
TEST_DEVICES=
ROUTER_ALLOWED_NETWORKS=$lantern_router_networks
SSH_ALLOWED_NETWORKS=$lantern_router_networks
ROUTER_WRITES_ENABLED=false
DEPLOYMENT_ENABLED=false
SSH_ENABLED=false
MFA_REQUIRED=false
MFA_LOGIN_REQUIRED=false
RECOVERY_ENABLED=false
LANTERN_TAG=0.1.0
EOF
fi
for lantern_key in signing ca; do
  if [ ! -f "data/keys/$lantern_key.key" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "data/keys/$lantern_key.key" 2>/dev/null
    openssl pkey -in "data/keys/$lantern_key.key" -pubout -out "data/keys/$lantern_key.pub"
  fi
done
if [ ! -f data/keys/ca.crt ]; then
  openssl req -x509 -new -key data/keys/ca.key -sha256 -days 3650 -subj '/CN=Lantern Device CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out data/keys/ca.crt
fi
if [ ! -f data/tls/server.crt ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 -subj "/CN=$lantern_ip" \
    -addext "subjectAltName=IP:$lantern_ip,DNS:$lantern_dns,DNS:localhost,IP:127.0.0.1" \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
    -out data/tls/server.crt -keyout data/tls/server.key 2>/dev/null
fi
chown -R 10001:10001 data
chmod 700 data data/keys data/repository data/recordings
chmod 600 .env data/keys/*.key
if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then chown "$SUDO_UID:$SUDO_GID" .env; fi
chown -R 10001:101 data/tls
chmod 750 data/tls
chmod 640 data/tls/server.key
chmod 644 data/tls/server.crt data/keys/*.pub data/keys/ca.crt
echo "Initialized. Review .env, then build/import images and run: docker compose up -d"
echo "Trust data/tls/server.crt on administrator browsers and agents; use a site CA for production."
