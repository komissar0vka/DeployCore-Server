#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $EUID != 0 ]]; then
  exec sudo bash "$PWD/install.sh" "$@"
fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ! ${VERSION_ID:-} =~ ^(22|24)\.04$ || $(uname -m) != x86_64 ]]; then
  printf 'Требуется Ubuntu 22.04 или 24.04 x86_64.\n' >&2
  exit 1
fi
[[ -f deploy/compose.yaml && -f deploy/.env.example ]]
if [[ -e deploy/.env ]]; then
  printf 'Конфигурация уже существует. Запускаю DeployCore с существующими настройками.\n'
else
  read -rp 'DNS-имя или IPv4-адрес, доступный компьютерам в локальной сети: ' host
  if [[ ! $host =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then
    printf 'Недопустимый адрес.\n' >&2
    exit 1
  fi
  read -rp 'HTTPS-порт [8443]: ' port
  port=${port:-8443}
  [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 ))
  read -rp 'Каталог с fullchain.pem и privkey.pem (Enter для самоподписанного сертификата): ' supplied_tls
  if [[ -n $supplied_tls ]]; then
    [[ $supplied_tls = /* && $supplied_tls != *[$'\r\n\t ']* && -r $supplied_tls/fullchain.pem && -r $supplied_tls/privkey.pem ]]
  fi
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1 || ! command -v openssl >/dev/null; then
  apt-get update
  if ! apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    apt-get install -y software-properties-common
    add-apt-repository -y universe
  fi
  apt-get install -y docker.io docker-compose-v2 openssl ca-certificates
  systemctl enable --now docker
fi
docker info >/dev/null
if [[ ! -e deploy/.env ]]; then
  tls=${supplied_tls:-./tls}
  san=DNS
  check_name=-checkhost
  if [[ $host =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    san=IP
    check_name=-checkip
  fi
  if [[ -z $supplied_tls && ! -e deploy/tls/fullchain.pem && ! -e deploy/tls/privkey.pem ]]; then
    mkdir -p deploy/tls
    openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=$host" \
      -addext "subjectAltName=$san:$host" -keyout deploy/tls/privkey.pem -out deploy/tls/fullchain.pem
  fi
  cert_dir=${supplied_tls:-deploy/tls}
  [[ -r $cert_dir/fullchain.pem && -r $cert_dir/privkey.pem ]]
  openssl x509 -in "$cert_dir/fullchain.pem" -noout -checkend 0 >/dev/null
  if ! openssl x509 -in "$cert_dir/fullchain.pem" -noout "$check_name" "$host" | grep -q 'does match certificate'; then
    printf 'TLS-сертификат не соответствует адресу %s.\n' "$host" >&2
    exit 1
  fi
  cert_key=$(openssl x509 -in "$cert_dir/fullchain.pem" -pubkey -noout)
  file_key=$(openssl pkey -in "$cert_dir/privkey.pem" -pubout)
  [[ $cert_key == "$file_key" ]]
  (
    set -o noclobber
    printf 'POSTGRES_PASSWORD=%s\nDEPLOYCORE_SETUP_TOKEN=%s\nDEPLOYCORE_HTTPS_BIND=0.0.0.0\nDEPLOYCORE_HTTPS_PORT=%s\nDEPLOYCORE_TLS_DIR=%s\nDEPLOYCORE_PANEL_URL=https://%s:%s\n' \
      "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$port" "$tls" "$host" "$port" > deploy/.env
  )
fi
compose=(docker compose --env-file deploy/.env -f deploy/compose.yaml)
if [[ -r deploy/.operations/compose.json ]]; then
  compose+=(-f deploy/.operations/compose.json)
fi
if [[ -r deploy/.updater/active.json ]]; then
  "${compose[@]}" -f deploy/.updater/active.json up -d --no-build --wait --wait-timeout 180
elif [[ -f deploy/release-images.json ]]; then
  install -d -m 700 deploy/.updater
  python3 deploy/scripts/release_images.py deploy/release-images.json > deploy/.updater/release-images.tmp
  if ! "${compose[@]}" -f deploy/.updater/release-images.tmp pull server web; then
    python3 deploy/scripts/release_images.py deploy/release-images.json --embedded > deploy/.updater/release-images.tmp
  fi
  mv -f deploy/.updater/release-images.tmp deploy/.updater/active.json
  "${compose[@]}" -f deploy/.updater/active.json up -d --no-build --wait --wait-timeout 180
else
  "${compose[@]}" up -d --build --wait --wait-timeout 180
fi
if [[ -d /run/systemd/system && ! -r deploy/.operations/compose.json ]]; then
  deploy/scripts/enable-operations.sh
fi
printf '\nВеб-панель: %s\n' "$(sed -n 's/^DEPLOYCORE_PANEL_URL=//p' deploy/.env)"
printf 'Откройте мастер настройки. Он запросит DEPLOYCORE_SETUP_TOKEN из %s/deploy/.env.\n' "$PWD"
printf 'Free активен автоматически и включает пять управляемых компьютеров.\n'
