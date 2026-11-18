# RESEARCH PLAN — NGINX2Root 분석·e2e·방어 환원 (v1.0)

작성일: 2026-11-19 · PI 결정: Mac(arm64)+DFIRtx 병행, 5건 전체 시도, 재현+독자 개선
근거: `GOAL-nginx2root-e2e.md` §0-2 · 브리핑 문서 [R1]-[R12]

## 0. 범위 선언

| 한다 | 하지 않는다 |
|---|---|
| 5건 CVE 소스 레벨 루트코즈 분석 | 커널 SCTP LPE 실증 (문서·점검만) |
| 123007 풀 RCE e2e 재현 (DFIRtx, 캐너리) | 실서비스·타인 시스템 대상 테스트 |
| 4건 UAF 크래시 트리거 자체 개발 | 무기화 페이로드 (리버스 셸 등) |
| 4-arm(취약/패치/완화/대조) 특이성 검증 | "성공률 높이기"만을 위한 무한 재시도 |
| 공격↔관측 상관으로 탐지 룰 실측 근거화 | 정상 트래픽 오탐 무시 탐지 룰 채택 |
| 전송량 절감·프로파일 일반화 등 독자 개선 측정 | 개선 성공의 외삽 주장 (측정 조건 명시) |

## 1. Phase 0 — 기준선·계층 교정

### 1-1. 자료 고정
- Rapid7 PoC(`poc-external/`), nginx 소스 1.31.8/1.31.9(`nginx-src/`) 확보 ✅ (11/19)
- 근거 체계 = 브리핑 문서의 [R1]~[R12] 인용 체계 습계. 신규 자료는 [R13+]로 추가.

### 1-2. 계층 비판·보정 (관측 인프라)

| # | 지적 | 수정 | 검증 |
|---|---|---|---|
| 1 | access.log엔 h2 제어 프레임이 남지 않는다 [R3][R7] | `h2_hunt` 포맷($connection_requests, request_length 등) + `ss -tinp` 주기 샘플 | A4 대조군에서 정상 분포 먼저 확보 |
| 2 | 크래시=공격 단정 금지 (GC/oom 등 대체 원인) | error.log `signal 11` + coredump + 동시간대 연결 상관 3축 | 크래시 원인 태깅 규칙 사전 고정 |
| 3 | Mac 에뮬 크래시는 재배포 불가 결과일 수 있음 | 에뮬 판정은 Mac-에뮬 프로파일로 한정 표기, DFIRtx 네이티브와 분리 기록 | E0에서 가부 확정 |
| 4 | RCE 성공 오탐(우리 스크립트 오작동) | 캐너리는 파일+모니터 출력 이중 확인 | monitor.sh 독립 경로 |

### 1-3. episode 정의 (실험 단위)
- **episode** = 하나의 arm 컨테이너 (재)기동 → 트리거/익스플로잇 1회 완주(성공·실패·타임아웃 불문) → 관측 수집 → 컨테이너 폐기.
- **attempt** = episode 내 재시도 1회 (e2e는 1 episode = 1 attempt 원칙: 힙 상태 오염 방지).
- 연속 시도는 독립 표본이 아님 → episode마다 컨테이너 재생성으로 독립성 확보.
- 기록 스키마 `exploit/results/<CVE>/<arm>/<epNN>/attempt_NN.json`:
  `ts, host_profile(arm, nginx_ver, glibc, cpu), input_params, duration_s, bytes_tx, verdict(T/R/C/I), evidence{crash_log, canary, monitor}, notes`

## 2. Phase 1 — 정적 분석 (국면 없이 즉시)

| 과제 | 방법 | 산출물 |
|---|---|---|
| 123007 루트코즈 | 1.31.8↔1.31.9 diff + 취약 트리 코드 추적 | `deep-analysis-CVE-2026-123007.md` |
| 4건 UAF 조건 | diff + 설정 요건(프록시/resolver/quic/mail) 역추적 | `deep-analysis-CVE-{4건}.md` |
| Rapid7 PoC 검증 | 코드 정독, 주장vs사실 분리 | `EXTERNAL-REVIEW-2026-11-19.md` |
| 동반 5건 | diff 식별 (방어 가이드용 요약) | vuln-analysis 부록 |

**G1 게이트**: 5건 루트코즈·트리거 조건 도출 완료 → CONTINUE. 단 123007만 완료돼도
123007 트리거 개발은 선착수 (나머지는 병행).

## 3. Phase 2 — 랩 구축 (4-arm)

| Arm | 이미지 | 설정 | 역할 |
|---|---|---|---|
| A1 취약 | nginx 1.31.8 | HTTP/2 on (TLS) | 공격 표적 |
| A2 패치 | nginx 1.31.9 | HTTP/2 on (동일) | 특이성 대조 (크래시 없어야 정상) |
| A3 완화 | nginx 1.31.8 | `http2 off` | 완화 효과 실측 |
| A4 대조 | nginx 1.31.9 | HTTP/2 on + 정상 부하(h2 부하생성기) | 탐지 룰 오탐 기준선 |

- 4건 노출 변형(conf variants): `proxy`(123633), `resolver+mirror`(123634),
  `quic`(121810), `mail+auth_http`(113425) — ops/docker/conf/
- 계층: h2_hunt access log, error.log, coredump(ulimit 해제), `ss` 샘플러,
  auditd execve(worker 자식), 파일 캐너리 감시.
- **E0 캘리브레이션(최우선 실험)**: Mac 에뮬 A1에서 simple-trigger 크래시 가부.
  결과가 관측불가(에뮬 memcpy 차이)면 Mac은 프레임 로직 검증 전용으로 격하,
  크래시·RCE는 DFIRtx로 이관 — 이 결정 자체를 E0 판정으로 기록.

## 4. Phase 3 — 트리거 개발 (판정어 사전 고정)

| 트리거 | 핵심 조건 | 판정 축 |
|---|---|---|
| trigger_123007 | 흐름제어 언더플로 유도 (공개 PoC 포팅+검증) | A1 크래시 / A2·A3 무해 |
| trigger_123633 | h2 draining + upstream 경합 (RST_STREAM·타임아웃 조합) | 〃 |
| trigger_123634 | 동적 resolver + mirror 서브리퀘스트 + DNS 지연 | 〃 |
| trigger_121810 | QUIC 스트림 종료 경합 (aioquic) | 〃 |
| trigger_113425 | mail 인증 흐름 + auth_http 시뮬레이터 | 〃 |

- 각 트리거 최소 10 episode(A1) + 3 episode(A2/A3 특이성). 10회 전 전부 실패 시
  조건 가설 재설계 1회 허용 후 재실험, 재실험도 실패 시 **미지지** 판정.
- 경합형(123633/634/1810/3425)은 소거 디버깅(ASAN/valgrind 빌드 보조) 허용.

**G2 게이트**: 123007 DFIRtx 크래시 재현 → e2e 착수. 미지지 → PIVOT(캐릭터라이징
중심). 4건은 트리거 확정 건만 e2e 후보.

## 5. Phase 4 — e2e·캐릭터라이징·독자 개선

1. **재현**: e2e_123007 (Rapid7 체인, 캐너리 종점) — 신선 컨테이너 프로파일에서 N=10 episode 성공률.
2. **캐릭터라이징**: (a) 부하 있는 worker(A1+배경 트래픽), (b) 대역폭 제한(tc),
   (c) 동시 클라이언트 — 각 축마다 성공률 변화 측정.
3. **독자 개선** (기준선과 동일 프로토콜로 비교):
   - I-a 전송량 절감 (프레임 크기·윈도우 시퀀스 최적화)
   - I-b glibc/CPU 프로파일 일반화 (avx512 비필수 경로 탐색 — [미확인] 표기 후 검증)
   - I-c 재시도·안정화 로직 (episode 내 오염 최소화 설계)
4. **G3 게이트**: 재현 실패 시에도 캐릭터라이징 부정 결과 + 방어 환원은 완주.

## 6. Phase 5 — 방어 환원

- 탐지 룰: 공격 episode 관측치 vs A4 정상 분포 → 임계값·시그니처 + 오탐률 명시.
- DEFENDER-GUIDE v1: OpenJDK2Shell v4 구조 계승(§0 가장 중요한 한 가지 … §8 한계).
- ops 스크립트 4종 랩 드라이런 검증.

## 7. 일정·세션 구분

| 세션 | 범위 |
|---|---|
| 1차 (11/19) | P0 전부, P1 123007+PoC 리뷰, P2 4-arm+E0, P3 123007 트리거 |
| 2차 | P1 나머지 4건, P3 UAF 트리거, DFIRtx e2e 재현 |
| 3차 | 캐릭터라이징·독자 개선, DEFENDER-GUIDE 완성 |

## 8. 리스크

| 리스크 | 완화 |
|---|---|
| DFIRtx 접근 불가 시 e2e 전체 지연 | E0에서 Mac 역할 확정, DFIRtx 도달 전 P1·P3 논리 검증 완료 상태 유지 |
| UAF 4건 경합 재현 난도 (공개 정보 부족) | 미지지도 유효 결과 — 조건 가설 문서화에 가치 |
| 에뮬/네이티브 결과 혼동 | host_profile 필드로 프로파일 분리 (계층 비판 #3) |
| 대용량 전송(수십 GiB) 랩 디스크·시간 부담 | loopback 우선, dfirtx 로컬 디스크 기록, 전송량 자체를 측정치로 보존 |

## 9. 즉시 착수 항목 (승인됨)

1. ✅ 저장소 골격·원칙 문서
2. ✅ 외부 자료 확보 (Rapid7 PoC, nginx 1.31.8/1.31.9)
3. ▶ 123007 diff 분석 + PoC 리뷰 (서브에이전트 진행 중)
4. vuln-analysis 기준선 → ops/docker 4-arm → E0 → trigger_123007
