#!/bin/bash
# mitigate.sh — 패치 전 임시 완화 적용·검증 (CVE-2026-123007/123633: HTTP/2 OFF)
# 사용:
#   bash mitigate.sh check [컨테이너명|호스트]   — 현재 상태·h2 협상 확인
#   bash mitigate.sh off   [conf경로=/etc/nginx/nginx.conf]  — http2 비활성화 적용
#   bash mitigate.sh verify HOST:PORT                        — ALPN으로 확인
# 주의: gRPC/HTTP/2 클라이언트 서비스 영향 사전 점검. reload 후 기존 h2 연결은
#       옛 worker에 남을 수 있음 → 필요 시 restart (DEFENDER-GUIDE §4).
set -euo pipefail
CMD="${1:-check}"
ARG2="${2:-}"

case "$CMD" in
check)
  T="${ARG2:-LOCAL}"
  echo "── 현재 h2 관련 지시어"
  if [ "$T" = "LOCAL" ]; then
    grep -RnE 'listen[[:space:]].*http2|http2[[:space:]]+(on|off)' /etc/nginx 2>/dev/null \
      || grep -RnE 'listen[[:space:]].*http2|http2[[:space:]]+(on|off)' /usr/local/nginx/conf 2>/dev/null || echo "  (없음)"
  else
    docker exec "$T" sh -c "grep -RnE 'listen[[:space:]].*http2|http2[[:space:]]+(on|off)' /etc/nginx /usr/local/nginx/conf 2>/dev/null" || true
  fi
  ;;
off)
  CONF="${ARG2:-/etc/nginx/nginx.conf}"
  [ -f "$CONF" ] || { echo "conf not found: $CONF" >&2; exit 1; }
  cp "$CONF" "$CONF.pre-mitigate.$(date +%s)"
  # nginx >= 1.25.1: 'http2 on' → 'http2 off'.  구버전: listen ... http2 에서 토큰 제거
  sed -i.bak -E 's/^([[:space:]]*)http2[[:space:]]+on[[:space:]]*;/\1http2 off;/' "$CONF"
  sed -i.bak -E 's/(listen[[:space:]][^;]*)[[:space:]]+http2([[:space:]]*;)/\1\2/' "$CONF"
  echo "── 적용 후:"
  grep -nE 'listen|http2' "$CONF" | head
  echo "── 구문검사 후 reload"
  nginx -t && nginx -s reload || { echo "검사 실패 — 백업에서 복구: $CONF.pre-mitigate.*"; exit 1; }
  echo "── 잔존 h2 리스너 확인 (없어야 함):"
  nginx -T 2>/dev/null | sed 's/#.*//' | grep -E 'listen[[:space:]].*http2|http2[[:space:]]+on' || echo "  OK: h2 리스너 없음"
  echo "── 기존 h2 연결·옛 worker 잔존 확인 필요 시 restart (가용성 영향 안내 후)"
  ;;
verify)
  [ -n "$ARG2" ] || { echo "사용: mitigate.sh verify HOST:PORT" >&2; exit 1; }
  H=${ARG2%%:*}; P=${ARG2##*:}
  R=$(echo | openssl s_client -connect "$H:$P" -servername "$H" -alpn h2 2>&1 | grep -E 'ALPN protocol|No ALPN' || echo "ALPN 정보 없음")
  echo "$H:$P → $R"
  case "$R" in *"h2"*) echo "⚠ 아직 h2 협상됨 — 완화 미적용/전파 안됨";; *) echo "OK: h2 미협상";; esac
  ;;
*)
  echo "사용: $0 {check|off|verify} …" >&2; exit 1 ;;
esac
