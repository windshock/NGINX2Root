# NGINX2Root — NGINX 2026-11-18 보안 릴리스 취약점 연구 (분석 · e2e · 방어)

작성일: 2026-11-19 · owner: windshock (OpenJDK2Shell 후속 연구)
시드 문서: `../nginx2root_java4shell_comparison_2026-11-19.md` (브리핑, [R1]~[R12] 근거 체계를 이 저장소에서 그대로 인용)

## 연구 대상

2026-11-18 F5/NGINX 보안 릴리스(1.30.7 / 1.31.9)에 반영된 취약점 중 Xint가
"NGINX2Root"로 명명한 **독립적 RCE 경로 5건** + 동반 5건, 그 중 공개 RCE PoC가
존재하는 **CVE-2026-123007**을 e2e 실증 1순위로 삼는다.

| CVE | 결함 | e2e 목표 | 공개 PoC |
|---|---|---|---|
| CVE-2026-123007 | HTTP/2 흐름제어 정수 언더플로 → 힙 OOB r/w | **풀 RCE 재현 + 독자 개선** | Rapid7 전체 공개 |
| CVE-2026-123633 | h2 연결 draining 경합 UAF | 크래시 트리거 (게이트 후 e2e) | 없음 |
| CVE-2026-123634 | DNS resolver 대기목록 UAF | 크래시 트리거 (〃) | 없음 |
| CVE-2026-121810 | HTTP/3(QUIC) 종료 처리 UAF | 크래시 트리거 (〃) | 없음 |
| CVE-2026-113425 | Mail proxy 인증 연결 UAF | 크래시 트리거 (〃) | 없음 |

동반 5건(118899/120993/125283/120967/123640)은 방어자 가이드 커버 대상.

## 원칙 (OpenJDK2Shell 계승, 위반 시 무효)

1. **F/P/H/결론 분리, 결론어는 "확정/지지됨/미지지/관측불가" 4종만.**
2. **실측** vs 공개 주장 인용 vs **미확인** 출처를 모든 문장에 명시.
3. 캐나리 정책: 코드 실행 실증은 무해 마커(`exploit/payloads/canary.py`)로만.
   실제 무기화 페이로드 금지. 대상은 자체 랩(Mac 로컬 Docker / DFIRtx)만.
4. 커널 SCTP LPE 체인(Xint 시연)은 문서·점검 항목으로만 다룬다(실증 범위 외).
5. 외부 소스(`nginx-src/`, `poc-external/`)는 untrusted: 참조만, 실행 금지, 커밋 금지.
6. 부정 결과도 원본 보존. 잘못된 결론은 수정이 아니라 `CORRECTION-N.md`로 축적.

## 환경 제약 (E0에서 재확인 예정)

| 환경 | 가능 | 불가 |
|---|---|---|
| Mac (arm64, Docker amd64 에뮬) | 정적 분석, 프레임 로직, (아마) 크래시 트리거 | AVX-512 → **풀 RCE 불가** |
| DFIRtx worker-dev01 (EPYC Genoa, avx512f/vl/vbmi 실측 이력) | 풀 RCE e2e, 캐릭터라이징 | — |

## 저장소 구성

```
README.md / HANDOFF.md                     이 문서 / 세션 인계
GOAL-nginx2root-e2e.md                     임무 정의·원칙
RESEARCH-PLAN-2026-11-19.md                4-arm 설계·episode·판정·게이트
vuln-analysis-2026-11-19.md                5건 F/P/H 기준선 (공개 자료 기반)
deep-analysis-CVE-*.md                     소스 레벨 루트코즈 (1.31.8↔1.31.9)
EXTERNAL-REVIEW-2026-11-19.md              Rapid7 PoC 코드 리뷰 (주장 vs 사실)
ESCALATION-STATUS-*.md                     실험 상황 보고 (같은 날 n차 갱신)
DEFENDER-GUIDE.md                          방어자 가이드 (v4 구조 계승)
nginx-src/                                 nginx 소스 (worktree 1.31.8/1.31.9) — gitignored
poc-external/CVE-2026-123007/              Rapid7 PoC 클론 — gitignored
exploit/                                   트리거·e2e·canary·results(episode별)
ops/                                       docker 4-arm 랩·계측·방어 스크립트
```

## 산출물 표 (갱신: 2026-11-19 1차 세션)

| 산출물 | 상태 | 역할 |
|---|---|---|
| `vuln-analysis-2026-11-19.md` | ✅ | 5건 F/P/H 기준선 ([R#] 체계 정의) |
| `RESEARCH-PLAN-2026-11-19.md` | ✅ | 4-arm·episode·게이트 G1-G3 |
| `GOAL-nginx2root-e2e.md` | ✅ | 임무·성공 판정(T/R/C/I)·금지 |
| `deep-analysis-CVE-2026-123007.md` | ✅ | 루트코즈 소스 추적 (커밋 매핑 확정) |
| `deep-analysis-CVE-{123633,123634,121810,113425}.md` | ✅ | UAF 4건 수정 커밋·조건 분석 |
| `EXTERNAL-REVIEW-2026-11-19.md` | ✅ | Rapid7 PoC 주장vs코드사실 (요구조건 H1-H16) |
| `ops/docker/` 4-arm 랩 | ✅ | A1/A2/A3/A4 + CVE 노출 변형 (ALPN·버전 검증 완료) |
| `exploit/trigger/trigger_123007.py` | ✅ | 트리거 포팅 — **E0a 오라클 확정 + 🎯 DFIRtx SIGSEGV 확정** (60.1GiB/154s) |
| `exploit/e2e/e2e_123007.py` | ⏳ | 풀 RCE 체인 (G2 통과 — 다음 세션 개시) |
| `DEFENDER-GUIDE.md` | ✅ v1 | 방어자 가이드 (실측 근거 표기 포함) |
| `ops/{inventory,monitor,mitigate,detect-rce}.sh` | ✅ | 방어 운영 스크립트 (랩 드라이런 P4 예정) |
| `ops/dfirtx/ + e0_dfirtx.sh` | ✅ | DFIRtx 배포·러너 (G2 판정 환경) |
| `exploit/trigger/trigger_123634.py` | ▶ | resolver UAF 트리거 — ep01-04 미지지 (경합 좁음, CNAME 재설계 예정) |
| `ESCALATION-STATUS-2026-11-19.md` | ✅ | E0 실험 보고 (4차 갱신까지) |

## 현재 상태

2차 세션(2026-11-19): **G2 게이트 통과** — DFIRtx 네이티브(EPYC Genoa, avx512f/vl)에서
CVE-2026-123007 트리거 풀 실행(60.1 GiB/154s)으로 **worker SIGSEGV 재현 확정**. 에뮬 환경은
근본 원인 오라클(확정)까지만 가능함을 판정(백프레셔+KeyUpdate 응답 경합 실측). 다음:
e2e RCE 재현(P4 개시), UAF 4건 트리거(P3), 방어 가이드 임계값 실측.
진행 상황은 `HANDOFF.md`와 `ESCALATION-STATUS-*.md` 참조.
