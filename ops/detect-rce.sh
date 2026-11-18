#!/bin/bash
# detect-rce.sh — NGINX worker 권한 코드 실행 징후 탐지 (호스트/Linux 대상, 읽기 전용)
# 축: (1) worker 자식 프로세스 (2) 크래시/코어덤프 (3) 이상 h2 연결 통계 (4) 캐너리
# 사용: bash detect-rce.sh [컨테이너명| --host]
set -uo pipefail
TARGET="${1:---host}"

run() {
  if [ "$TARGET" = "--host" ]; then sh -c "$1"; else docker exec "$TARGET" sh -c "$1"; fi
}

echo "══ 1. NGINX worker 자식 프로세스 (RCE 가장 강력 징후 — 부모 UID 확인 필수)"
run "ps -eo pid,ppid,user,comm,args | grep '[n]ginx: worker' " | while read -r pid ppid rest; do
  run "ps -eo pid,ppid,args | awk -v p=$ppid '\$2==p'" 2>/dev/null | grep -vE 'nginx|ps ' && \
    echo "⚠ worker(pid=$pid)의 자식 존재"
done || true

echo "══ 2. 크래시/코어덤프 (최근)"
run "grep -iE 'exited on signal|signal 11|segfault' /var/log/nginx/error.log 2>/dev/null | tail -5" \
  || docker logs "$TARGET" 2>&1 | grep -iE 'exited on signal|signal 11' | tail -5 \
  || echo "  (없음)"
run "ls -la /cores 2>/dev/null | tail -3"

echo "══ 3. 이상 h2 연결 (장시간·고수신·저응답 = 트리거/그루밍 정황)"
run "ss -tinp state established 2>/dev/null | grep -A1 ':443' | head -20" || true
echo "  판정 기준(DEFENDER-GUIDE §3): 수신 바이트 ≫ access.log request_length 합계 +\
동일 IP 다중 연결 + 직전 worker crash 상관 — 단일 신호로 단정 금지"

echo "══ 4. 캐너리/마커 (침해대응 시 이미 존재할 수 있는 흔적 포함)"
run 'ls -la /tmp/n2r-canary-* /tmp/rapid7-nginx-h2-proof-* 2>/dev/null' || echo "  (없음)"

echo "══ 5. auditd 권고(호스트 전용)"
if [ "$TARGET" = "--host" ] && command -v auditctl >/dev/null 2>&1; then
  cat <<'EOF'
권장 규칙 (nginx worker 실행계정의 execve):
  -a always,exit -F arch=b64 -S execve -F euid=101 -k nginx_child
  (euid=nginx 실행계정으로 조정; auditd 재시작 없이 auditctl -R 적용)
EOF
else
  echo "  (컨테이너 대상/auditctl 없음 — 호스트에서 실행 권장)"
fi
