#!/bin/bash
# inventory.sh — NGINX 자산 점검 (DEFENDER-GUIDE §1 연동)
# 대상: 원격 NGINX 호스트에서 실행 (또는 docker exec). 읽기 전용.
# 사용: bash inventory.sh [--docker]
set -euo pipefail
DOCKER="${1:-}"

hr() { echo "══ $1 ══"; }

if [ "$DOCKER" = "--docker" ]; then
  NGINX=/usr/local/nginx/sbin/nginx
else
  NGINX=$(command -v nginx || echo /usr/sbin/nginx)
fi

hr "1. 바이너리 버전·빌드 (HTTP/2·v3 모듈 컴파일 여부)"
$NGINX -v 2>&1
$NGINX -V 2>&1 | tr ' ' '\n' | grep -E -- '--with-http_v[23]_module|--with-mail|--with-stream' || echo "  (관련 모듈 없음)"

hr "2. 활성 설정 (http2/quic/resolver/mirror/proxy_pass/auth_http)"
if [ -x /usr/local/nginx/sbin/nginx ] && [ ! -f /etc/nginx/nginx.conf ]; then
  CONF_DIR=/usr/local/nginx/conf
else
  CONF_DIR=/etc/nginx
fi
${NGINX} -T 2>/dev/null | sed 's/#.*//' | grep -nE \
  'listen[[:space:]].*(http2|quic)|http2[[:space:]]+(on|off)|http3[[:space:]]+(on|off)|proxy_pass|resolver[[:space:]]|mirror|auth_http|proxy[[:space:]]+on' \
  | head -40 || echo "  (nginx -T 실패 — 권한 확인)"
echo "  주의: nginx -T 전체 출력에는 인증서 경로·업스트림이 포함됨 — 외부 공유 금지"

hr "3. 실행 중인 nginx 프로세스 (master/worker 권한 분리 확인)"
ps -eo pid,ppid,user,args | grep '[n]ginx' || true

hr "4. 리스너 (443/tcp, 443/udp=QUIC, 143 등 메일)"
(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E ':(443|80|8443|143|993|995)[[:space:]]' || true
(ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null) | grep ':443[[:space:]]' && echo "  ^^ UDP/443 = QUIC 리스너" || true

hr "5. ALPN h2 협상 외부 확인 안내"
echo "  openssl s_client -connect HOST:443 -servername HOST -alpn h2 </dev/null 2>&1 | grep 'ALPN'"
echo "  → CDN/프록시 경유면 원본 직접 확인 필요 (DEFENDER-GUIDE §2)"

hr "6. 코어덤프·최근 크래시 흔적"
(docker logs "$2" 2>&1 | grep -iE 'signal 11|segfault' | tail -3) 2>/dev/null \
  || grep -iE 'signal 11|segfault' /var/log/nginx/error.log 2>/dev/null | tail -3 \
  || echo "  (최근 크래시 라인 없음 또는 권한 없음)"

hr "요약 판정 기준 (DEFENDER-GUIDE §1)"
cat <<'EOF'
[긴급] 1.31.8 이하(또는 1.30.6 이하 stable) + HTTP/2 ON + 외부 도달  → CVE-2026-123007/123633 노출
[점검] quic 리스너 → 121810 · 변수 proxy_pass+resolver+mirror → 123634 · mail+auth_http → 113425
[유의] 배포판 백포트 패치 여부는 패키지 버전(예: dpkg -l nginx / rpm -q nginx)으로 별도 확인
EOF
