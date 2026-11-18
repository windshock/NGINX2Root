#!/bin/sh
# NGINX2Root 랩 엔트리포인트: 자가서명 인증서 생성 + core dump 활성화 + nginx foreground
set -e

CERT_DIR=/usr/local/nginx/conf/certs
if [ ! -f "${CERT_DIR}/server.crt" ]; then
    mkdir -p "${CERT_DIR}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.crt" \
        -subj "/CN=nginx2root-lab" >/dev/null 2>&1
    echo "[entrypoint] generated self-signed cert"
fi

mkdir -p /cores /usr/local/nginx/logs
# 코어덤프: compose ulimits(core:-1)와 병행. working_directory /cores 는 conf에서 지정.
ulimit -c unlimited 2>/dev/null || true

echo "[entrypoint] starting nginx $(/usr/local/nginx/sbin/nginx -v 2>&1)"
exec /usr/local/nginx/sbin/nginx -g 'daemon off;'
