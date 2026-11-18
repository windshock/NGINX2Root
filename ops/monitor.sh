#!/bin/bash
# monitor.sh — worker 크래시·자식 프로세스·캐너리 상시 감시 (랩/운영 겸용)
# 사용: bash monitor.sh [nginx컨테이너명=LOCAL | --host]   Ctrl-C로 종료
set -uo pipefail
MODE="${1:-LOCAL}"
STATE=/tmp/n2r-monitor.state
: > "$STATE"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

worker_pids() {
  if [ "$MODE" = "--host" ]; then
    pgrep -f 'nginx: worker process' || true
  else
    docker exec "$MODE" sh -c "pgrep -f 'nginx: worker process'" 2>/dev/null || true
  fi
}

snapshot() { worker_pids > "$STATE.now"; }

# 자식 프로세스 감시: worker가 execve한 /bin/sh·curl·wget·touch (RCE 강력 징후)
check_children() {
  local pids child
  pids=$(worker_pids)
  [ -z "$pids" ] && return 0
  if [ "$MODE" = "--host" ]; then
    child=$(ps -eo pid,ppid,comm | awk -v p="$pids" 'BEGIN{split(p,a," ")}{for(i in a) if($2==a[i]) print}' | grep -vE 'nginx' | head)
  else
    child=$(docker exec "$MODE" sh -c \
      "ps -eo pid,ppid,comm 2>/dev/null | grep -E 'sh|curl|wget|touch|id' | grep -v grep" 2>/dev/null | head)
  fi
  [ -n "$child" ] && { log "⚠ WORKER CHILD PROCESS (RCE 징후):"; echo "$child"; }
}

check_canary() {
  local f
  for f in /tmp/n2r-canary-01 /tmp/n2r-canary-id /tmp/rapid7-nginx-h2-proof-01; do
    if [ "$MODE" = "--host" ]; then
      [ -f "$f" ] && log "◎ CANARY HIT: $f ($(stat -c '%u:%g' "$f" 2>/dev/null))"
    else
      docker exec "$MODE" sh -c "[ -f $f ] && echo HIT:$f \$(stat -c '%u:%g' $f)" 2>/dev/null \
        | while read -r l; do log "◎ CANARY HIT: $l"; done
    fi
  done
}

log "monitoring mode=$MODE (worker 크래시·자식 프로세스·캐너리)"
snapshot
while true; do
  sleep 2
  snapshot
  NEW=$(comm -13 "$STATE" "$STATE.now" 2>/dev/null || true)
  if [ -n "$NEW" ]; then
    # worker PID 교체 = 크래시 또는 reload. error.log와 상관 필수 (계측 3축)
    log "↻ worker PID 변경 감지 (신규: $(echo $NEW | tr '\n' ' ')) — 크래시 가능성, error.log 확인:"
    if [ "$MODE" = "--host" ]; then
      tail -3 /var/log/nginx/error.log 2>/dev/null
    else
      docker logs --tail 3 "$MODE" 2>&1
    fi
    mv "$STATE.now" "$STATE"
  else
    : > "$STATE.now" 2>/dev/null || true
  fi
  check_children
  check_canary
done
