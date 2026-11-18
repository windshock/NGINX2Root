# HANDOFF — 세션 인계

갱신: 2026-11-19 (1차 세션 진행 중) · 저장소: `/Users/1004276/Downloads/nginx`

## 한 줄 요약

NGINX2Root(2026-11-18 NGINX 보안 릴리스) 5건 CVE에 대한 분석·e2e·방어 가이드
프로젝트. 1차 세션은 Phase 0(기준선) 완료, Phase 1(소스 분석)·Phase 2(랩) 진행.

## 규칙 요약 (전체는 GOAL-nginx2root-e2e.md)

1. 결론어 4종만: 확정/지지됨/미지지/관측불가. F/P/H 분리.
2. 실측 vs 공개 주장 인용 vs 미확인 명시. 근거는 [R#] 체계.
3. 캐너리만, 자체 랩만(Mac 에뮬/DFIRtx), 무기화 금지, SCTP LPE는 문서만.
4. 부정 결과 보존, 정정은 CORRECTION-N.md.

## 문서 지도

| 문서 | 역할 |
|---|---|
| README.md | 개요·원칙·산출물 표 |
| GOAL-nginx2root-e2e.md | 임무·성공 판정(T/R/C/I)·금지 |
| RESEARCH-PLAN-2026-11-19.md | 4-arm·episode 스키마·게이트 G1-G3 |
| vuln-analysis-2026-11-19.md | 5건 F/P/H 기준선 ([R#] 체계 정의) |
| deep-analysis-CVE-*.md | 소스 레벨 루트코즈 (작성 중) |
| EXTERNAL-REVIEW-2026-11-19.md | Rapid7 PoC 주장vs사실 (작성 중) |
| DEFENDER-GUIDE.md | 방어자 가이드 (P5, 미작성) |

## 현재 상태 (11/19 1차 세션 종료 시점)

- ✅ Phase 0: 골격·원칙·연구계획·F/P/H 기준선·외부 자료
- ✅ Phase 1: 5건 deep-analysis (커밋 매핑 확정 — changes.xml 명시) + EXTERNAL-REVIEW
- ✅ Phase 2: 4-arm 랩 검증 (A1 1.31.8+h2 / A2 1.31.9+h2 / A3 h2off / A4) + debug arm
- ✅ **E0a: 근본 원인 오라클 재현 확정** (A1dbg, 54.4s, 21.7MB, avx512 없는 에뮬) —
  A2 패치·A3 완화에서 재현 안 됨 (특이성 실측). `ESCALATION-STATUS-2026-11-19.md` §1
- ▶ E0b (A1 full ≈60GiB 크래시) 백그라운드 진행 — 결과는 attempt JSON + crash_log.txt
- ✅ DEFENDER-GUIDE v1 + ops 방어 스크립트 4종

## 다음 세션 시작 명령

1. 이 파일과 `RESEARCH-PLAN-2026-11-19.md` §9, `ESCALATION-STATUS-2026-11-19.md` 최신판 읽기
2. `git log --oneline` 확인. 랩 상태: `bash ops/run_local.sh verify` (미기동 시 `up`)
3. E0b 결과 확인: `exploit/results/CVE-2026-123007/a1/ep06-full/` — 크래시 여부가
   P4 역할 분담(DFIRtx 이관 필요성) 판정 기준
4. DFIRtx 접근 방법 확인(OpenJDK2Shell ops/ 자료 참조) → G2 게이트: e2e_123007 재현

## 남은 과제

1. E0b 판정 확정 + ep02 정지 원인(non-debug A1 worker 4) 재현 분석
2. A2 디버그 arm에서 패치 분기 지점 관측 (oracle-reset vs oracle-sync)
3. DFIRtx e2e_123007 재현 (G2) + 캐릭터라이징·독자 개선 (P4)
4. UAF 4건 트리거 개발 (P3) — 랩 변형 conf·헬퍼(slowback/dnssim/authsim/imapsim) 구비 완료
5. 방어 스크립트 랩 드라이런 + DEFENDER-GUIDE 임계값 실측 갱신 (P5)
