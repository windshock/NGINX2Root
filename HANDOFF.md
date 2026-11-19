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

## 현재 상태 (11/20 3차 세션 종료 시점)

- ✅ 1-2차 세션 전부 (기준선·분석·랩·E0a 오라클·G2 SIGSEGV·DEFENDER-GUIDE v1)
- 🎯 **핵심 목표 달성: 풀 RCE 10/10 재현 (R-확정)**
  - 타깃 = Rapid7 검증 digest `nginx@sha256:5ab5b0b…` 고정, golden 프로파일 수정 없이 통과
  - 119.02GiB/≈288s(278-301s), 캐너리 파일+uid:gid 101:101 이중 오라클, episode 10건
  - `exploit/results/CVE-2026-123007/a1-dfirtx/ep{01..10}-rce/`
- ✅ 특이성 확정 (DFIRtx 네이티브): A2(1.31.9) 오라클 단계 거부·무해 / A3(h2 off) ALPN 거부·무해
  — A2 1차 시도는 랩 conf 오류로 무효(보존), 수정 후 유효 판정
- ✅ 캐릭터라이징 1축: 오염 힙(정상 부하 60s 선오염+지속) → **실패** (`leak ambiguous: 0
  candidates`, 302s, fail-closed 실측) — H3 예비 지지 (N=1)
- ✅ 탐지 실측: RCE 진행 중 수신:송신 **277:1**(119.9GB vs 0.43GB) — DEFENDER-GUIDE §3-B 갱신,
  access.log 제어프레임 무로그도 실측 확인
- ▶ 미완: 캐릭터라이징 나머지 축(대역폭·동시성), 독자 개선(I-a/b/c), UAF 4건 트리거,
  방어 스크립트 드라이런

## 다음 세션 시작 명령

1. 이 파일 + `RESEARCH-PLAN-2026-11-19.md` §9 + `ESCALATION-STATUS-2026-11-19.md` §9-10 읽기
2. 우선순위 제안: (a) UAF 4건 트리거 — 123634 CNAME 경로 재설계(dnssim에 CNAME 응답 추가)
   → 123633(작은 worker_connections conf 변형) → 121810(QUIC, trixie 빌드) → 113425(mail)
   (b) 캐릭터라이징 대역폭 축(tc netem 또는 클라이언트측 제한) (c) 독자 개선 I-a 전송량 절감
3. DFIRtx: `ops/e0_dfirtx.sh up` (재기동 ~2분, ns는 종료 시 삭제됨) → `prepare` → 실험
4. 세션 종료 시 `ops/e0_dfirtx.sh down` + `ops/spec_dfirtx.sh down` (위생 규칙)

## 남은 과제

1. UAF 4건 트리거 (P3) — 123634 CNAME 재설계가 1순위 (경로 도달은 확인됨)
2. 캐릭터라이징: 대역폭 축·동시성 축 (오염 힙 축은 1회 완료 — N 늘리면 더 강해짐)
3. 독자 개선 I-a(전송량 절감)/I-b(프로파일 일반화)/I-c(안정화) — 기준선 288s·119GiB가 비교 기준선
4. 방어 스크립트(inventory/monitor/mitigate/detect-rce) 랩 드라이런 + 가이드 임계값 보강
5. (선택) A4 대조군 부하 하 탐지 룰 오탐률 측정 — DEFENDER-GUIDE §3-B 임계값 확정
