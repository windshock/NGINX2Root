#!/bin/bash
# NGINX2Root 랩 로컬 기동 (Mac 검증용) — RESEARCH-PLAN §3
# 사용:
#   ops/run_local.sh up [profile]   # 기본 core, 또는 debug|a4|cve123633|cve123634|cve121810|cve113425
#   ops/run_local.sh verify         # 4-arm 기동 검증 (버전·ALPN·페이지)
#   ops/run_local.sh down
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f ops/docker/compose.yaml"
PROFILE="${2:-core}"

case "${1:-up}" in
up)
  $COMPOSE --profile "$PROFILE" up -d --build
  echo "── 기동됨 (profile=$PROFILE). 포트: A1 8443 A2 8444 A3 8445 A4 8446"
  ;;
verify)
  echo "── 컨테이너/버전"
  for c in n2r-a1 n2r-a2 n2r-a3 n2r-a4; do
    v=$(docker exec "$c" /usr/local/nginx/sbin/nginx -v 2>&1 || echo "down")
    echo "  $c: $v"
  done
  echo "── ALPN (A1/A2/A4=h2, A3=h2 아님)"
  python3 ops/check_alpn.py 127.0.0.1:8443 127.0.0.1:8444 127.0.0.1:8445 127.0.0.1:8446
  echo "── 페이지"
  curl -sk https://127.0.0.1:8443/ ; curl -sk --http2 https://127.0.0.1:8444/
  ;;
down)
  $COMPOSE --profile "$PROFILE" down -v
  ;;
logs)
  $COMPOSE logs -f --tail 50
  ;;
crashes)
  for c in n2r-a1 n2r-a2 n2r-a3 n2r-a4; do
    echo "── $c error.log (worker crash 라인)"
    docker logs "$c" 2>&1 | grep -iE 'signal 11|segfault|exited on signal|core' | tail -5 || true
    echo "  cores: $(docker exec "$c" ls -la /cores 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')개"
  done
  ;;
*)
  echo "사용: $0 {up|verify|down|logs|crashes} [profile]" >&2
  exit 1
  ;;
esac
