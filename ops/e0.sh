#!/bin/bash
# E0 캘리브레이션 러너 — amd64 에뮬 클라이언트 컨테이너에서 trigger_123007 실행 + 서버측 크래시 확인
# 사용: ops/e0.sh <a1|a2|a3|a4> <episode명> [--smoke|--full] [host-profile]
#   예) ops/e0.sh a1 ep01 --smoke
set -euo pipefail
cd "$(dirname "$0")/.."

ARM="${1:?arm required (a1|a2|a3|a4)}"
EP="${2:?episode name required (e.g. ep01)}"
MODE="${3:---smoke}"
PROFILE="${4:-mac-docker-emul}"

case "$ARM" in
  a1) C=n2r-a1 ;;  a2) C=n2r-a2 ;;  a3) C=n2r-a3 ;;  a4) C=n2r-a4 ;;
  a1dbg) C=n2r-a1dbg ;;
  *) echo "unknown arm $ARM" >&2; exit 1 ;;
esac

NET="nginx2root-lab_default"
CLIENT_IMG="nginx2root/client:py310"

# 클라이언트 이미지 (CPython 3.10 + OpenSSL 3, amd64 에뮬)
docker build --platform linux/amd64 -q -t "$CLIENT_IMG" - <<'EOF' >/dev/null
FROM python:3.10-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 procps && rm -rf /var/lib/apt/lists/*
EOF

# 프레시 힙: 시도 전 타깃 재시작 (EXTERNAL-REVIEW §5.2-5)
echo "── restarting $C (fresh worker heap)"
docker restart "$C" >/dev/null
sleep 1

echo "── running trigger (arm=$ARM mode=$MODE)"
EXTRA=""
[ "$MODE" = "--smoke" ] && EXTRA="--smoke"
docker run --rm --platform linux/amd64 --network "$NET" \
  -v "$PWD/exploit:/work/exploit" \
  "$CLIENT_IMG" \
  python3 /work/exploit/trigger/trigger_123007.py \
    --target "https://$C:443/" --arm "$ARM" --episode "$EP" \
    --host-profile "$PROFILE" $EXTRA || true

# 서버측 증거 수집 (계측 3축: error.log crash 라인 + 코어)
EPDIR="exploit/results/CVE-2026-123007/$ARM/$EP"
mkdir -p "$EPDIR"
echo "── server-side crash check ($C)"
if docker logs "$C" 2>&1 | grep -iE 'exited on signal|signal 11|segfault' | tail -5 | tee "$EPDIR/crash_log.txt"; then
  echo "── cores:"; docker exec "$C" ls -la /cores 2>/dev/null | tail -n +2 || true
  echo "E0 RESULT: crash CONFIRMED on $ARM"
else
  echo "E0 RESULT: no crash lines on $ARM"
fi
