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

## 현재 상태 (11/19 2차 세션 종료 시점)

- ✅ 1차 세션 전부 (기준선·분석·랩·E0a 오라클·DEFENDER-GUIDE v1)
- ✅ E0b 에뮬 판정 확정: 정체 원인 = **백프레셔+TLS KeyUpdate 응답 경합** (SSL_read
  WANT_WRITE → 읽기 정지), send_timeout 무관(ep08), 비결정적(ep03 통과/ep07-08 정체) →
  **Mac 크래시 관측불가 → DFIRtx 이관 판정**
- 🎯 **G2 게이트 통과**: DFIRtx worker-dev01(EPYC Genoa, avx512f/vl 실측) 네이티브에서
  트리거 풀 실행 → **SIGSEGV 확정** (60.1GiB/154s, `worker exited on signal 11`)
  — `exploit/results/CVE-2026-123007/a1-dfirtx/ep09-firtx-full/`
- ✅ DFIRtx 인프라: `ops/dfirtx/{target,client}.yaml` + `ops/e0_dfirtx.sh` (up/smoke/
  full/pull/down, 위생 규칙 ns 삭제 구현). nginx:1.31.8 공식 이미지 = trixie/OpenSSL
  3.5.7 — **Rapid7 golden 프로파일 환경과 동일 계열** (e2e RCE에 유리)
- ▶ P3: trigger_123634 ep01-04 미지지 (경로 도달 확인, 경합 미달) — dnssim 클래스 구조
  버그 수정 완료(무응답 원인). CNAME/SRV 경로가 가설 재설계 후보
- ✅ trigger_123633/121810/113425: 미개발 (랩 변형 conf·헬퍼는 구비)

## 다음 세션 시작 명령

1. 이 파일 + `RESEARCH-PLAN-2026-11-19.md` §9 + `ESCALATION-STATUS-2026-11-19.md` §8 읽기
2. G2가 통과했으므로 **e2e RCE 재현(P4)이 최우선**: DFIRtx `ops/e0_dfirtx.sh up` →
   클라이언트 pod에 `pip install cryptography` + streamer 빌드(cc -O2 exploit 대상은
   poc-external/exploit/streamer.c) → EXTERNAL-REVIEW §5.3 체크리스트 순서로 실행
   (공식 이미지+glibc 2.41 프로파일 = 현재 타깃과 일치 — 프로파일 수정 최소화 기대)
3. 캐릭터라이징(P4): 신선 컨테이너 N=10 episode 성공률 → 부하/대역폭/동시성 축
4. UAF 4건: 123634 CNAME 경로 재설계 → 123633(worker_connections 소진 conf) 순
5. 세션 종료 시 `ops/e0_dfirtx.sh down` (위생 규칙)

## 남은 과제

1. **e2e_123007 RCE 재현 (DFIRtx)** — G2 통과, 게이트 열림. 캐너리 판정 R.
2. A2/A3 특이성의 DFIRtx 네이티브 보강 (에뮬 특이성은 이미 확정)
3. 캐릭터라이징·독자 개선 측정 (P4: I-a 전송량 절감, I-b 프로파일 일반화, I-c 안정화)
4. trigger_123634 CNAME 경로 재설계 + trigger_123633/121810/113425 개발
5. 방어 스크립트 랩 드라이런 + DEFENDER-GUIDE 탐지 임계값 실측 갱신 (P5)
