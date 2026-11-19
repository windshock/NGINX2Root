#!/usr/bin/env python3
"""summarize_baseline.py — e2e RCE 기준선 episode JSON 집계 (RESEARCH-PLAN §5-1).

사용: python3 ops/summarize_baseline.py
출력: N episode 중 R-확정 수, 성공률, 소요시간 통계. ESCALATION-STATUS 인용용.
"""
import glob
import json
import statistics

recs = []
for p in sorted(glob.glob("exploit/results/CVE-2026-123007/a1-dfirtx/ep*-rce/attempt_*.json")):
    d = json.load(open(p))
    ep = p.split("/")[-3]
    recs.append((ep, d.get("verdict"), d.get("exploit_exit")))

n = len(recs)
confirmed = sum(1 for _, v, _ in recs if v == "R-확정")
print("episode 수: %d" % n)
for ep, v, rc in recs:
    print("  %-12s verdict=%s exit=%s" % (ep, v, rc))
if n:
    print("R-확정: %d/%d = %.0f%%" % (confirmed, n, 100.0 * confirmed / n))
