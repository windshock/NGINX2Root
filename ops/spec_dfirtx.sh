#!/bin/bash
# 특이성 검증 (DFIRtx 네이티브) — 같은 트리거가 A2/A3에서 무해함을 실측
# 사용: ops/spec_dfirtx.sh up | a2-full | a3-smoke | down
set -euo pipefail
cd "$(dirname "$0")/.."

KC="kubectl --kubeconfig ${KUBECONFIG:-/Users/1004276/Downloads/OpenJDK2Shell/kube/dfirtx-dev.conf}"
NS=n2r-test
a2pod() { $KC get pod -n $NS -l app=n2r-a2 -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
a2ip()  { $KC get pod -n $NS -l app=n2r-a2 -o jsonpath='{.items[0].status.podIP}' 2>/dev/null; }
a3pod() { $KC get pod -n $NS -l app=n2r-a3 -o jsonpath='{.items[0].metadata.name}' 2>/dev/null; }
a3ip()  { $KC get pod -n $NS -l app=n2r-a3 -o jsonpath='{.items[0].status.podIP}' 2>/dev/null; }

case "${1:-a2-full}" in
up)
  $KC apply -f ops/dfirtx/spec.yaml
  $KC wait -n $NS --for=condition=Ready pod -l app=n2r-a2 --timeout=180s
  $KC wait -n $NS --for=condition=Ready pod -l app=n2r-a3 --timeout=180s
  echo "A2=$(a2pod) $(a2ip) / A3=$(a3pod) $(a3ip)"
  ;;
a2-full)
  # A2(1.31.9 패치)에 풀 트리거 → 크래시 없음이 특이성 실측
  IP=$(a2ip)
  echo "── A2 ($IP) 풀 트리거 실행 (≈4분)"
  set +e
  $KC exec -n $NS n2r-client -- python3 -u /work/exploit/trigger/trigger_123007.py \
      --target "https://$IP:443/" --arm a2-dfirtx --episode "ep01-a2-full" \
      --results-root /work/results --host-profile dfirtx-genoa-native 2>&1 | tail -4
  RC=$?
  set -e
  sleep 2
  echo "── A2 크래시 라인:"
  $KC logs -n $NS "$(a2pod)" --tail=30 2>/dev/null | grep -iE 'exited on signal|signal 11' \
    && echo "⚠ A2에서 크래시 — 특이성 위반(재검토 필요)" || echo "OK: A2 무해 (특이성 지지)"
  ;;
a3-smoke)
  # A3(1.31.8 h2off)에 스모크 → ALPN h2 거부가 완화 실측
  IP=$(a3ip)
  echo "── A3 ($IP) 스모크 실행"
  set +e
  $KC exec -n $NS n2r-client -- python3 -u /work/exploit/trigger/trigger_123007.py \
      --target "https://$IP:443/" --arm a3-dfirtx --episode "ep01-a3-smoke" \
      --results-root /work/results --host-profile dfirtx-genoa-native 2>&1 | tail -3
  set -e
  echo "── A3 크래시 라인:"
  $KC logs -n $NS "$(a3pod)" --tail=30 2>/dev/null | grep -iE 'exited on signal|signal 11' \
    && echo "⚠ A3에서 크래시" || echo "OK: A3 무해 (완화 지지)"
  ;;
down)
  $KC delete -f ops/dfirtx/spec.yaml 2>/dev/null || true
  echo "특이성 arm 삭제"
  ;;
*) echo "사용: $0 {up|a2-full|a3-smoke|down}" >&2; exit 1 ;;
esac
