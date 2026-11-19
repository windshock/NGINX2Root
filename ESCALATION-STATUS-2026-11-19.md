# ESCALATION STATUS — 1차 세션 실험 보고 (2026-11-19)

체계: 모든 판정은 **실측** 근거. 결론어 4종(확정/지지됨/미지지/관측불가)만 사용.
환경: Mac (Docker linux/arm64 위 amd64 에뮬 — **avx512 부재 실측**, `grep avx512 /proc/cpuinfo` 공백).

## 1. 요약

| 실험 | 대상 | 결과 | 판정 |
|---|---|---|---|
| E0a ep01 | A1 (본문 24B) | 풀 요청 2,728개 > max_concurrent_streams(128) → 오라클 미달성 | 관측불가 (설계 오류 — 896B 프로파일로 수정) |
| E0a ep02 | A1 (본문 896B) | sendall 600s 타임아웃 — nginx가 플라이트 미소비 (Recv-Q 2.58MB 정지) | 관측불가 (원인 미상 — §3 참조) |
| **E0a ep03** | **A1dbg (worker 1, 본문 896B)** | **"cleanup over-credit confirmed" — 근본 원인 오라클 재현** | **확정** |
| E0a ep04 | A2 (1.31.9 패치) | 오라클 미달성 (스트림 리셋 단계부터 상이) | 미지지 (패치 특이성 — 정상) |
| E0a ep05 | A3 (h2 off) | TLS `no application protocol` — h2 협상 거부 | 미지지 (완화 특이성 — 정상) |
| E0b ep06 | A1 풀 체인(≈60GiB) | 진행 중 (백그라운드) | 진행 중 |

**핵심 결과: CVE-2026-123007의 근본 원인(클린업 오버크레딧 → 부호 없는 검증 언더플로 수용)이
AVX-512 없는 에뮬 환경에서도 재현됨.** 54.4초, 클라이언트→서버 21,782,171B (≈21.7MB).
오라클 3요소(타깃 스트림 FLOW_CONTROL_ERROR 리셋 / 10바이트 공개 방출 / 손상 커넥션에서
PING ACK 수신) 모두 관측. 디버그 로그로 `http2 close stream 155` 이벤트 처리 확인.

## 2. 이번 run의 신호

- **A1dbg 서버 로그** (23:02): 이벤트 프레임 소비 → `http2 close stream 155` → PING ACK 송신 —
  오버크레딧 상태에서 커넥션이 살아 프레임을 수용 = 검증 우회의 직접 관측 (deep-analysis §2-⑤와 일치)
- **A2(패치)**: 같은 입력으로 오라클 미달성 — `send_queued` 반영 검증식이 회계 파괴를 차단하는
  방향의 실측 차이 (정확히 어느 단계에서 갈리는지는 A2 디버그 실행으로 보강 가능 — 남은 것 §5)
- **A3(완화)**: ALPN h2 거부 — 완화 유효성 실측 (DEFENDER-GUIDE §2 근거로 반영)

## 3. 시행착오 (보존)

1. **ep01**: 본문 24B → 소진 방정식에 풀 요청 2,728개 필요 → nginx 기본 max_concurrent_streams
   128 초과. 교정: 랩 이미지 index.html을 정확히 896B로 고정 (Rapid7 프로파일 전제 재현).
   트리거 자체는 프로브 측정으로 적응하나, 스트림 수 폭증은 프로파일 문제임을 학습.
2. **ep02**: non-debug A1(worker 4)에서 nginx가 14.4MB 플라이트 소비 정지 (Recv-Q 2.58MB 고정,
   2분+ 무변화) → 클라이언트 sendall 600s 타임아웃. A1dbg(worker 1)에서는 동일 로직 통과.
   가설: (a) 에뮬 타이밍·이벤트 루프 지연 누적 (b) worker 수에 따른 커넥션-워커 배치 차이 —
   미확정. A1 재시도 예정(§5).

## 4. 자산

| 파일 | 역할 |
|---|---|
| `exploit/trigger/trigger_123007.py` | 포팅 트리거 (적응형 본문 측정·episode 기록·--smoke) |
| `exploit/common/{h2,rawtls,episode}.py` | 공용 프레임/TLS/기록 모듈 |
| `ops/e0.sh` | E0 러너 (프레시 힙 restart·클라이언트 컨테이너·서버 로그 크로스체크) |
| `exploit/results/CVE-2026-123007/{a1,a1dbg,a2,a3}/ep*/attempt_01.json` | episode 기록 |

## 5. 남은 과제 (다음 세션)

1. **E0b 완료 판정** (ep06, 진행 중): 크래시 여부 + 전송량·소요시간 기록. 에뮬 처리량 한계로
   장시간 소요 예상 — 실패 시 "Mac 관측불가, DFIRtx 이관" 판정도 유효 (RESEARCH-PLAN §1-2 계측 비판 #3)
2. A2 디버그 arm 실행 — 패치가 정확히 어느 단계에서 궤를 분기시키는지 관측 (oracle-reset vs oracle-sync)
3. ep02 정지 원인 재현/분석 (A1 재시도 ± worker_processes 고정)
4. DFIRtx 접근 — 풀 RCE(G2 게이트) + 캐릭터라이징
5. UAF 4건 트리거 개발 (P3) — 랩 변형(conf)·헬퍼는 구비 완료

## 6. 11/19 2차 갱신 — E0b 1차 시도 관측 (23:0x-23:1x)

- ep06 (A1 full): 이벤트 플라이트 전송 중 **클라이언트 sendall 600s 타임아웃**. 서버측:
  - Recv-Q가 1,229,742B에서 60초+ 완전 고정 (ep02는 2,579,386B — 정지값은 회차별 상이)
  - nginx 에러 로그 **완전 무음** (flood/timeout/prematurely closed 부재) — 이벤트 루프
    정체 징후 (read 이벤트 미처리 추정)
  - ep02(스모크)와 동일 패턴 → **a1(worker auto=10)에서 재현성 있는 정지**
- 정지 vs 통과 조건 격리: a1dbg(worker 1)는 ep03에서 동일 플라이트 통과 →
  후보 변수: worker_processes 수, 로그 레벨, 타이밍. ep07(a1dbg full)로 격리 진행 중.

## 7. 11/19 3차 갱신 — E0b 상태 및 소스 단서 (23:2x)

- **소스 단서 (실측, ngx_http_v2_read_handler)**: 읽기 루프는
  `h2c->total_bytes / 8 > h2c->payload_bytes + 1048576` 시 "http2 flood detected"로
  GOAWAY — ep02/ep06에서 이 로그는 **없었음** → 플러드 검사 발동이 아니라 그 이전에
  read 이벤트 자체가 진행되지 않은 것. `send_output_queue`의 `send_timeout` 타이머도
  발동 안 함(에러 무음) → nginx worker가 해당 커넥션의 이벤트 처리를 멈춘 상태.
- ep07 (a1dbg full) 백그라운드 진행 중 — 결과는 attempt_01.json + crash_log.txt로 기록.
- **현재까지의 E0 결론 (사전 고정 판정 규칙 적용)**:
  - 오버크레딧(근본 원인) 재현: **확정** (AVX-512 불요 실측)
  - 패치/완화 특이성: **확정** (A2 오라클 미달성, A3 h2 거부)
  - Mac 에뮬에서 크래시(E0b): **관측불가 상태로 진행 중** — a1 정지 원인 규명 또는
    DFIRtx 이관 필요 (RESEARCH-PLAN §1-2 계측 비판 #3 그대로 적용)

## 8. 11/19 4차 갱신 — E0b 에뮬 판정 확정 + 🎯 G2 게이트 통과 (DFIRtx SIGSEGV)

### 에뮬 정체 원인 (관측 확정 — ep07 디버그 로그)

```
23:16:44 SSL_read: -1 → SSL_get_error: want write   ← 핵심
23:16:44 client timed out (110) → 408 → close stream 153/155 (queued 1)
23:16:44 worker cycle / epoll timer: -1             ← 이후 완전 idle
```

- **메커니즘**: 클라이언트 백프레셔(RCVBUF 1024, sendall 중 미판독) 상태에서 nginx의
  TLS 출력(KeyUpdate 응답)이 TCP 윈도 0으로 막히면 **SSL_read가 WANT_WRITE로 블록** →
  nginx 읽기 정지 → 클라이언트 sendall 교착. send_timeout 60s가 캐리어/릴리즈 응답을
  408 조기 종료시키는 부수 현상도 관측.
- **send_timeout 무관 재확인**: ep08(600s 변형)도 동일 정체 (Recv-Q 355KB 고정).
- **비결정성**: ep03(스모크)은 동일 조건에서 want-write 없이 전체 플라이트(21.7MB) 통과.
  → 에뮬 처리 속도+커널 버퍼 상태에 따라 회차별로 갈리는 경합. 원본 PoC 환경(네이티브
  amd64)은 재현문서가 정상 작동 입증 — **에뮬 한계로 판정**: Mac 크래시(E0b) = 관측불가,
  DFIRtx 이관 (계획대로).

### 🎯 G2 게이트 통과 — DFIRtx 네이티브 크래시 재현 (ep09, T-확정)

| 항목 | 값 (실측) |
|---|---|
| 환경 | DFIRtx worker-dev01 pod, EPYC Genoa (**avx512f+avx512vl 실측**), nginx:1.31.8 공식 이미지(trixie, OpenSSL 3.5.7), linux/amd64 네이티브 |
| 트리거 | trigger_123007.py 풀 모드 — 128 트랜슈, **60.1 GiB**, 154.31초 |
| 오라클 | cleanup over-credit confirmed (스모크 ep09도 통과) |
| **크래시** | **`worker process 32 exited on signal 11`** (SIGSEGV, 클라이언트 연결 사망 + 서버 로그 이중 확인) |
| episode | `exploit/results/CVE-2026-123007/a1-dfirtx/ep09-firtx-{smoke,full}/` + crash_log.txt |
| 대조 | 이번 세션 A2/A3 특이성(에뮬)과 DFIRtx A2/A3 특이성은 다음 세션 보강 예정 |

- Rapid7 재현문서 기준(≈60GiB, 189s)과 실측 규모·시간 일치 — **공개 PoC의 크래시 주장 재현 =
  지지됨에서 확정으로 승격** (우리 랩에서의 실측).
- 배포 매니페스트·러너: `ops/dfirtx/{target,client}.yaml`, `ops/e0_dfirtx.sh` (지문 확인
  ALPN h2 + 896B + 4 worker). 위생 규칙 준수 — ns n2r-test 종료 시 삭제 완료(재기동 ~2분).
- **다음 단계(G2 통과에 따라 개시 가능)**: e2e RCE 재현 — 클라이언트 pod에 cryptography
  의존성 + streamer 빌드 필요 (EXTERNAL-REVIEW §5.3 체크리스트).

### dnssim 수정 (실측)

- ep01에서 resolver가 재전송만 반복 — 원인: dnssim 헬퍼의 **서버/핸들러 클래스 구조 오류**
  (RequestHandlerClass=None → handle 미호출, 무응답). 수정 후 3.0s 지연 응답 실측 확인.
- trigger_123634 ep01-04: **미지지** (경로 도달은 확인 — 리졸브 완료·upstream 502·mirror
  704 이벤트, 그러나 ALERT/crash 없음). 경합이 외부 타이밍만으로는 좁음.
  가설 재설계 후보(RESEARCH-PLAN §4의 1회 허용분): **CNAME 응답 경로**(8492a8b8a 인접 코드)
  + SRV — dnssim에 CNAME 지원 추가 필요. 다음 세션 과제.

## 9. 11/19 5차 갱신 — 🎯🎯 R-확정: 풀 RCE 재현 성공 (ep01-rce)

**인증 없는 HTTP/2 입력 → NGINX worker 권한 코드 실행 체인 완전 재현.**

| 항목 | 값 (실측) |
|---|---|
| 환경 | DFIRtx worker-dev01 pod 네이티브 amd64 (avx512f/vl) |
| 타깃 | **nginx@sha256:5ab5b0b…** — Rapid7 재현문서가 검증한 공식 이미지 digest와 동일 (Image ID 확인) |
| 프로파일 | golden-nginx-1.31.8-debian13-amd64 (수정 없이 그대로 적용) |
| 클라이언트 deps | cryptography 49.0.0 (requirements 정확 버전) + streamer `nginx-rce-streamer/2` 재빌드 |
| 소요 | **293.71초**, 평문 **119.02 GiB**, 보조 연결 16 |
| ASLR 해석 | H=0x55f304b71020 · nginx=0x55f302cc0840 · libc=0x7fdd815cd000 · system=0x7fdd81620090 (인밴드 ELF 심볼 해석) |
| **캐너리 판정** | **R-확정** — /tmp/n2r-canary-01, /tmp/n2r-canary-id 모두 **uid:gid=101:101**(nginx worker) 소유. 파일 존재 + 소유자 이중 오라클 |
| episode | `exploit/results/CVE-2026-123007/a1-dfirtx/ep01-rce/` + exploit 로그 |

- 사전 고정 판정(GOAL §2): **R (RCE) = 캐너리 + 모니터 이중 확인 → 확정.**
- 의의: 공개 PoC의 RCE 주장이 **우리 랩에서 처음부터 끝까지 검증**됨. 프로파일 수정 없이
  원본 그대로 적용됨 — EXTERNAL-REVIEW의 "버전 전용 프로파일은 부족" 경고가 예측한 대로,
  공식 이미지 digest 고정이 정합성을 결정.
- 랩 시간 참고: CNI 경유로 Rapid7 기록(189-223s)보다 ~70s 느림 (293s) — 대역폭 차이일 뿐,
  성공 조건에는 영향 없음. **[측정]**
- DEFENDER-GUIDE §3-A를 실측 근거로 갱신: RCE 성공 시 worker 계정(101:101)의 산출물이 남는다는
  사실이 이제 재현된 사실.
- 진행 중: N=10 기준선 (ep02-rce~ep10-rce, episode마다 pod 재생성으로 독립 표본) —
  완료 시 성공률 산출 → RESEARCH-PLAN §5-1.

## 10. 11/20 6차 갱신 — 기준선 완주 10/10 + 특이성·캐릭터라이징 1축 확정

### N=10 기준선 (프레시 pod, digest 고정) — **R-확정 10/10 = 100%**

| ep01-ep10 | 전부 R-확정 (캐너리 파일 + uid:gid 101:101 이중 오라클) |
|---|---|
| 소요시간 | 278.29–301.45초 (평균 ≈288s, 표준편차 ≈7s — 매우 안정적) |
| episode | `exploit/results/CVE-2026-123007/a1-dfirtx/ep{01..10}-rce/` |

### 특이성 (DFIRtx 네이티브 — H1 실측 확정)

| Arm | 결과 | 판정 |
|---|---|---|
| A1 (1.31.8, digest 고정) | 트리거 SIGSEGV + RCE 캐너리 10/10 | (기준선) |
| **A2 (1.31.9 패치)** | **오라클 단계 실패**(target 스트림 FLOW_CONTROL_ERROR 리셋 없음) → 크래시 없음 | **무해 — 특이성 지지** |
| **A3 (1.31.8 + h2 off)** | **ALPN h2 거부**(`no application protocol`) → 진입 차단 | **무해 — 완화 지지** |

- A2 1차 시도는 랩 구성 오류(기본 conf로 기동 — 접속 거부)로 **무효 episode**; conf 수정
  (n2r-nginx-conf 마운트 + gencert initContainer) 후 유효 재시도. 시행착오 보존 원칙에 따라 기록.
- A2의 오라클 실패 위치가 deep-analysis §1의 수정 내용(`send_queued` 반영 검증)과 정합 —
  회계 파괴 이벤트가 패치 빌드에서 거부됨.

### 캐릭터라이징 1축 — 오염 힙 (H3, 예비 N=1)

- 조건: 정상 HTTPS 부하(curl loop) 60초 선오염 + e2e 진행 중 부하 지속, pod 재시작 없음.
- 결과: **실패** — bootstrap/carrier(15GiB)/WU replay/힙 그루밍/누출(14,393B)까지 성공,
  **ASLR 해석 단계에서 `leak ambiguous: 0 candidates`** (302.40s, 캐너리 없음).
- 해석: **H3 지지됨(예비)** — Rapid7의 "오염된 초기 힙에서 실패" 주장을 자체 실측으로 재확인.
  누출은 발생했으나 그 지문이 프로파일과 매칭 안 됨 → 오염이 할당 패턴을 바꿈.
  fail-closed 설계(오판 없이 안전 중단)도 실측.
- 한계: N=1, 오염 방식이 Rapid7(동시 클라이언트 16)과 다름 — 2차 축(대역폭·동시성)은 미측정.

### 라이브 트래픽 스냅샷 (탐지 실측 — ep06 진행 중 관측)

- 타깃 pod eth0: **수신 119.9GB vs 송신 0.43GB (비대칭 ≈277:1)**, RX 패킷 1,230만.
- access.log는 이 트래픽을 소수 요청 라인으로만 기록(제어 프레임 무로그 실측 확인) →
  DEFENDER-GUIDE §3-B를 실측 근거로 갱신 (파일 계측 필요성 포함).

## 11. 11/20 7차 갱신 — UAF 트리거 개발: 경로 활성 확인, 크래시 미지지

### trigger_123633 (drain UAF) — 10 episode

| 축 | 결과 |
|---|---|
| **drain 경로 활성** | **10/10** — `reusing connection` 이벤트, WARN `worker_connections are not enough` 2/10. 트리거 토폴로지(부분 HEADERS 커넥션 + 패딩 + 동시 신규 접속)가 drain을 실제로 유발함을 실측 |
| UAF 크래시 | **미지지** (0/10 SIGSEGV) |

- 랩 변형: `ops/docker/conf/proxy-small.conf` (worker_connections 16, worker_processes 1,
  debug 로그) — drain 임계(free ≤ connection_n/16)에 빠르게 도달시키는 설계.
- 메커니즘 재확인(소스): handle_connection:670-674가 **불완전 프레임 대기 커넥션도
  reusable=1 등록** + handler를 idle_handler로 교체(:692). drain(ngx_connection.c:1435+)은
  c->close=1 후 read->handler 동기 호출. 1.31.9 수정(2df48a501)은 create_stream에서
  reusable=0.
- 미달 원인 분석: drain 콜백이 골라낸 커넥션의 커널 버퍼에 완성분이 "도착했으나 미처리"
  상태여야 경합이 성립 — 외부 타이밍으로 그 정렬을 만들기 어려움 (ep01-10은 완성분이
  별개 이벤트로 처리됨). 재설계 후보: accept-drain 직후 정렬(TCP 전송 타이밍 세밀 제어).

### trigger_123634 (resolver UAF) — 재설계(가설 1회 허용) + 10 episode

- **dnssim CNAME 지원 추가**: `<name>.c<D>.test` → CNAME → `x.d<D>.test`(지연 A) /
  `<name>.c<D>nx.test` → CNAME → `x.d<D>.nx.test`(지연 NXDOMAIN). 실측: CNAME RR 인코딩 확인.
- **경로 활성 실측**: alias 이름 질의 161회 → nginx가 CNAME을 따라 별칭 `x.d3.test` 재질의 →
  161개 대기 ctx가 **CNAME 재시작 경로**(8492a8b8a 인접 코드)로 별칭 노드 대기목록에 흡수.
- ALERT `could not cancel` / 크래시: **0/10 — 미지지**.
- **ALERT 미발화 원인 확정(소스 실측)**: `ngx_resolve_name_done()`의 ALERT 조건은
  `ctx->state == NGX_AGAIN 또는 TIMEDOUT` AND ctx가 rn->waiting에 없음. 정상 보고 루프는
  handler 호출 **전에** ctx->state를 갱신하므로, "자기 ctx"의 done()은 ALERT 없이 통과.
  UAF는 **보고 루프 전체 탈착 직후, 미래 ctx(state 갱신 전)를 다른 핸들러가 done()할 때**만
  성립 → 동기 취소 벡터가 필요.
- **재설계 방향 확정 (다음 세션)**: **SRV 경로** — done()의 `ctx->nsrvs` 재귀가 자식 ctx들을
  동기 취소(ngx_resolver.c:539-541) = "다른(미래) ctx를 done()"의 실현 가능한 벡터.
  랩 구성: `upstream { server <이름> service=http resolve; }` (1.31.8 지원 실측 —
  ngx_http_upstream.c:6682) + dnssim에 SRV 응답 지원 추가 + 지연 자식 + 중단 겹침.

### 자산

| 파일 | 역할 |
|---|---|
| `exploit/trigger/trigger_123633.py` + `ops/run_123633.sh` + `conf/proxy-small.conf` | drain UAF 트리거 체계 |
| `exploit/trigger/trigger_123634.py` (--mode direct/cname/cname-nx) + dnssim CNAME | resolver UAF 트리거 체계 |
| `exploit/results/CVE-2026-123633/a1/ep01-10/` · `CVE-2026-123634/a1/ep01-10/` | episode + 서버 관측 기록 |

## 12. 11/20 8차 갱신 — E-V 증거 검증: 탐지 시그니처 실측 확정 (ep12-verif)

부모 가이드 체크리스트의 "미실측 추론" 항목을 실측으로 승격시키는 검증 실험.
h2_hunt 포맷 + 전체 컨테이너 로그 수집 conf로 타깃을 재배포하고 RCE 1회를 재실행
(R-확정, 311.99s, 119.02 GiB — h2_hunt conf가 프로파일 정합성을 깨지 않음도 확인).

### 검증 결과 (타깃 컨테이너 로그 전량 529줄, `ep12-verif/target_container_logs.txt`)

| 항목 | 이전 | 실측 |
|---|---|---|
| ① 캐리어 흔적 | 추론 (16777xxx 예상) | **request_length=50331645 × 320줄** — HEADERS+CONTINUATION
  3프레임 합산(3×16,777,215). **원 제안 grep은 실제 값을 놓쳤을 것** → 시그니처 교정:
  "max frame size 정수배의 초대형 request_length 다발" |
| ② 커넥션 요청 수 | 74까지 직접 관측 | **requests=519** (PoC 회계 74+3+320+96+…와 정확 일치) |
| ④ glibc 메시지 | 미캡처 | **`double free or corruption (!prev)`** — stderr 평문. SIGCHLD와
  signal 6 사이 타이밍 |
| ③ 재확인 | 3 episode | 동일: worker SIGCHLD(자식 포크=system()) → signal 6 (SIGABRT) |
| ⑤ auditd | 미실측 | 미실측 유지 (랩 무 auditd — EDR 환경 검증은 별도 과제) |

### 운영자 시그니처 최종본 (전 항목 실측)

```
access.log: request_length=50331645 ×320 / 한 출발지 / 수 분   ← 캐리어 (15 GiB 회계)
access.log: requests=519 (단일 conn)                          ← 커넥션 소진
error.log:  worker의 "SIGCHLD received from N"                ← system() 실행 (자식 포크)
stderr:     "double free or corruption (!prev)"               ← 힙 손상 텍스트 증거
error.log:  exited on signal 6 (RCE 후 지연 붕괴) vs signal 11 (시도 — 실행 전 OOB)
```

### 시사점

1. **추론 시그니처는 실측 전까지 신뢰 금지** — ①의 예상값(16777xxx)은 실측값(50331645)과
   달랐다. CONTINUATION 프레임이 request_length에 합산되는 것이 원인.
2. 성공 RCE는 무음이 아니다: SIGCHLD + glibc 텍스트 + signal 6의 3중 흔적.
   glibc 메시지는 nginx error.log가 아닌 **프로세스 stderr** 경로 — 수집 설계 주의.
3. DEFENDER-GUIDE §5-4에 실측 표 반영 완료 (단일 PoC 프로파일 한정 명시).

### 기타

- A2(패치 arm) 특이성: conf 교정 후 풀 트리거 재실행 → **oracle-reset 미달성 + 무크래시**
  (T-미지지 = 패치 반응). episode JSON은 runner 로그에서 복원(원본은 ns 정리로 소실).
- E-V 후 ns n2r-test 삭제 (위생 규칙).
