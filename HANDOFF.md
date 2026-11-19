# HANDOFF — 세션 인계

갱신: 2026-11-20 (4차 세션 종료) · 저장소: `/Users/1004276/Downloads/nginx`

## 한 줄 요약

NGINX2Root(2026-11-18 NGINX 보안 릴리스) 5건 CVE 연구. **123007 풀 RCE 10/10 재현(R-확정)
달성**, 특이성·오염힙·탐지 실측 완료. 4차 세션: UAF 2건 트리거 개발 — 경로 활성은 확정,
크래시는 미지지(경합 미달), SRV 재설계 방향 확정.

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

## 현재 상태 (11/20 4차 세션 종료 시점)

- ✅ 1-3차 세션 전부 — **핵심 목표(123007 풀 RCE 10/10 R-확정) 달성 상태 유지**
- ✅ trigger_123633 (drain UAF): **drain 경로 활성 10/10 확정** (`reusing connection`,
  WARN 2/10) / UAF 크래시 미지지 0/10. 랩 변형 proxy-small.conf(worker_connections 16)
- ✅ trigger_123634 재설계(가설 1회 허용): dnssim CNAME 지원 추가 → **CNAME 재시작 경로
  활성 실측** (alias 질의 161회 → 별칭 x.d3.test 재질의, 161 ctx 흡수) / ALERT·크래시
  미지지 0/10
- ✅ **ALERT 미발화 원인 소스 확정**: done()의 ALERT 조건은 `state==NGX_AGAIN|TIMEDOUT`
  AND waiting 미탈착 — 정상 보고 루프는 handler 호출 전 state를 갱신하므로 자기 ctx의
  done()은 통과. UAF 성립 조건 = **보고 루프 전체 탈착 직후, 미래 ctx(갱신 전)를 다른
  핸들러가 done()** → 동기 취소 벡터 필요
- ✅ 재설계 방향 확정: **SRV 경로** — done()의 nsrvs 재귀(ngx_resolver.c:539-541)가 자식
  ctx 동기 취소 = 실현 가능한 "미래 ctx done()" 벡터. 랩 구성: `upstream { server <이름>
  service=http resolve; }` (1.31.8 지원 실측, ngx_http_upstream.c:6682) + dnssim SRV 응답
- ▶ 미개발: trigger_121810(QUIC), trigger_113425(mail) — 랩 변형 conf·헬퍼는 구비

## 다음 세션 시작 명령

1. 이 파일 + `ESCALATION-STATUS-2026-11-19.md` §11 읽기
2. 우선순위 제안:
   (a) **123634 SRV 재설계** — dnssim에 SRV 응답 지원(_http._tcp.<이름>) + resolver.conf에
   `upstream { server srv1.test service=http resolve; }` 변형 + 자식 지연·중단 겹침
   (b) 123633 accept-drain 정렬(완성분 전송을 drain 콜백 직후로 세밀 제어)
   (c) 121810(QUIC, trixie 빌드+quic.conf+aioquic) / 113425(mail+authsim 지연)
   (d) 캐릭터라이징 대역폭·동시성 축 + 독자 개선 I-a/b/c
3. Mac 랩은 기동 상태 유지 가능 (compose profiles). 세션 종료 시 불필요하면 down.

## 남은 과제

1. 123634 SRV 재설계 실험 (가설 재설계 2차 — RESEARCH-PLAN §4 허용 범위 재검토 시 기록)
2. 123633 타이밍 정렬 재시도 / 121810·113425 트리거 개발
3. 캐릭터라이징 대역폭·동시성 축 / 독자 개선 I-a(전송량 절감)·I-b(프로파일 일반화)·I-c(안정화)
   — 기준선: 288s·119GiB·10/10
4. 방어 스크립트 랩 드라이런 + A4 오탐률 측정
5. 최종 산출물 정리 (README·가이드 최종본, CORRECTION 필요 시)
