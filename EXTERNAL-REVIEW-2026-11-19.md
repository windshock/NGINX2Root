# EXTERNAL REVIEW — Rapid7 CVE-2026-123007 공개 PoC 검증 (주장 vs 코드 사실)

작성일: 2026-11-19 · 대상: `poc-external/CVE-2026-123007/` 커밋 (11/19 클론, 정적 리뷰만 — 미실행)
체계: **코드 확인** = 소스로 확인된 사실 · **문서 주장** = README/재현문서 서술(코드로 재검증 안 됨) · **미확인**
구조: `exploit/exploit.py`는 런처(10줄)이고 실체는 `exploit/nginx_rce/` 패키지(11 모듈 ≈3,470줄) + `streamer.c`(328줄, 네이티브 대량전송 헬퍼) + `profiles/*.json`(타깃 ABI 프로파일).

## 0. 한 줄 결론

**트리거(≈60 GiB, 크래시)와 RCE(119.02 GiB, worker 권한 명령 실행)의 전송량·구조 수치는 코드로 확인된다.**
반면 성공률(연속 성공/실패 기록), avx512 필요성(코드 검사 없음), "다른 레이아웃 가능" 경고 등은
**문서 주장**이며 우리 랩에서 episode로 재검증할 대상이다. e2e 성공 입증은 외부 오라클(마커 파일)이
유일하고, 익스플로잇 종료 상태만으로는 부족하다 — 재현문서 스스로 명시. **[코드 확인]**

## 1. simple-trigger-poc.py — 근본 원인 오라클 + 크래시 증폭기

### 1.1 메커니즘 (코드 확인)

**핵심: WINDOW_UPDATE의 경계검사가 `MAX - current`를 부호 없는 값으로 계산하는 것.**
커넥션 윈도우가 MAX(2^31-1)를 초과하는 불법 상태가 되는 경로:

1. **커넥션 윈도우 65,535 정밀 소진**: 프로브 2 + 풀 71 + Range 127B 요청으로 `2·896 + 71·896 + 127 = 65,535` (simple:216-231)
2. **TCP 백프레셔** (RCVBUF/CLAMP=1024): 응답 DATA는 예약되지만 송신 불가 상태 (237-238)
3. **0-윈도우 스트림 2개(149/151)의 DATA 예약**: 스트림 크레딧만 부여, 커넥션 크레딧은 0 유지 (243-247)
4. **근본 원인 이벤트** (257-260):
   - `WU(0,1792)` 대기 DATA 반환 → 커넥션 윈도우 0
   - `WU(0,MAX)` → MAX
   - `WU(149,MAX-1)·WU(151,MAX-1)` → 각 스트림 윈도우 = 65,535 + MAX-1
   - `SETTINGS(INITIAL_WINDOW_SIZE,+2)` → 스트림 윈도우 2^31 = **불법 → FLOW_CONTROL_ERROR 리셋** →
     클린업이 예약됐던 2×896B를 커넥션 윈도우로 반환 → **커넥션 윈도우 = MAX+1792 > MAX**
   - `WU(0,MAX)`: `MAX - current` 부호 없는 언더플로 → MAX 증가분 **잘못 수락** (250-256 주석)
5. **캐리어/단일 TLS 플라이트**: 이벤트를 7,340,032B HEAD 캐리어 뒤에 배치 + **KeyUpdate 262,144회**
   (ctypes로 `SSL_key_update` 직접 호출 — CPython 3.10 `ssl.SSLObject` 내부 레이아웃 의존, 279-288)로
   nginx 파서/출력 경계를 결정론화 (273-278 주석; TLS 취약점 아님 명시)
6. **오라클**: 149/151의 FLOW_CONTROL_ERROR 리셋 + Range 응답 정합성 + PING ACK = "cleanup over-credit confirmed" (303-336)
7. **크래시 증폭** (342-392):
   - 플러드 예산: 16MiB HEAD 요청 512개(≈8 GiB) — 초소형 WU 프레임 52 GiB의 "정당한 입력 회계" (339-341, 힙 그루밍 아님 명시)
   - **부호 있는 윈도우 전환**: 13B `WU(0,MAX)` 프레임을 **2^32회** 전송(128트랜스×32전송×1MiB) →
     64비트 커넥션 윈도우가 부호 있는 중간점(2^63) 통과 → **음수** (364-367)
   - 트랜스 사이 오너 교체(RST CANCEL + 신규 1바이트 Range)로 음수 구간 DATA 미방출·타임아웃 회피 (368-371)
   - `WU(sink,1)` → 음수 출력 한도에서 nginx가 **역전된 버퍼** 생성 → 거대 겉보기 길이가 TLS memcpy로 (383-387)
   - midpoint 값이 비정규(noncanonical) 엔드포인트 → 치명적 경로 = SIGSEGV (385-387 주석)

### 1.2 전송량·판정

- 클라이언트→서버 ≈ **60 GiB** (7MiB 부트 + 8 GiB 플러드 예산 + 52 GiB WU 시퀀스). 서버→클라이언트 수 MiB 미만. **[코드 확인]**
- 크래시 판정: 연결 끊김 단독 불가 — **docker log의 `exited on signal 11` 확인 필수** (재현문서 요구). **[코드/문서 확인]**

## 2. exploit.py (nginx_rce 패키지) — RCE 체인 6단계

| Phase | 함수 | 내용 (코드 확인) |
|---|---|---|
| A 부트스트랩 | bootstrap.bootstrap | 위 트리거와 동일한 회계 버그 구축. **TLS 키 인계**: keylog에서 CLIENT_TRAFFIC_SECRET_0을 읽어 RecordWriter가 송신 레코드를 직접 생성(protocol.py:232-307) — 클라이언트가 TLS 시퀀스 완전 소유. 인밴드 프로파일링: 서버 SETTINGS 지문·`server` 헤더·본문 크기 버킷으로 타깃 확인(63-89) |
| B 음수 윈도우 | reach_wrapped_window | 캐리어 960×16,777,215B = **15.00 GiB 평문**(320 HEAD 요청) + `WU(0,MAX)` **2^33+1회**를 96 오너로 분할 재생 → 커넥션 윈도우 = **-14,392** (negative_distance). 전송은 streamer.c 네이티브(상수 메모리), JSON 원장으로 프레임/바이트 정합 검증(bulk.py:94-136) |
| C 보조 연결 | open_auxiliaries | **16개** 독립 TLS/h2 세션(윈도우 0). 용도: worker 4개 중 리클레임 후보가 메인과 같은 worker에 떨어질 확률 장치(16/4 비둘기집) + 리클레임 청크 사전 할당 |
| D 힙 그루밍 | prepare_reclaim_stage | HPACK 워밍 → 보조별 핀(8×2,552B) → B(블로커/미러/drain/final 2,552B 'A') → **C = B 다음 청크의 request pool(피해자)** 구성 → 16 선행 핀 → donor 부분 헤더('J'×5,135 마지막 1B 보류) → 보조 부분 요청(K/L/E 필드, H 길이 바이트 직전까지) → 단일 이벤트로 H 완성+소스 확보(4,095B 제어 청크 해제→sink가 복사 소스로 재사용) |
| E 누출+ASLR | capture_and_forge | `WU(0,tailored)` → PING 938+SETTINGS 37(프로파일러 맞춤 공간 소진) + RST(donor) + `WU(sink,65535)` + `WU(0,14393)` → **래핑된 복사 발동** → sink에서 8,192+6,201=**14,393B 누출** 캡처 → H 청크 시그니처(size 5,153, fd/bk arena 포인터)로 **libc base** + 자기참조 풀로 **H** + PIE 앵커(캐노니컬 0x400000000000-0x800000000000 + 델타 {0,-464,-13568})로 **nginx base** → 1.31.8은 "주소 지시형": 살아있는 요청의 write_handler·복제 ngx_http_request_t·가짜 connection(send=nginx+139,856)·chain/buf(flags 0x22)로 임의 주소(libc ELF 영역)를 DATA로 방출하는 위조 H 조립 |
| F 리클레임+실행 | release_and_dispatch | 보조 16개가 미완결 프레임 완성 → B-free 배리어(PING ACK) → 보조가 B 청크(4,095) 재점유로 **C의 pool cleanup 포인터(pool+64)를 H로 교체** → `RST(C)`로 디스패치 → 두 번째 누출로 **ELF64 DT_HASH/STRTAB에서 `system` 심볼 인밴드 해석**(memory.py:401-486) → 늦은 'E' 풀 스텁(cleanup={system, cmd}, 핸들러=nginx-398,896) → `WU(0,1)` 마지막 1바이트 해제 → **`system(cmd)` 실행** |

- 명령 제약: ≤120B, NUL 금지. **재시도 로직 없음(단발)**, 모든 게이트 fail-closed. **[코드 확인]**
- 성공 입증: 익스플로잇 외부 오라클 필수 — 마커 파일 `touch /tmp/rapid7-nginx-h2-proof-01` + `stat` UID/GID=101(nginx worker). **[문서 주장→우리 프로토콜 채택]**

## 3. 외부 주장 vs 우리 실측 (정합성 표)

| 항목 | 외부 문서/코드 주장 | 우리 실측 | 정합성 |
|---|---|---|---|
| 전송량 119.02 GiB (RCE) | runner.py 회계식 + 원장 검증 | 미측정 (P4 예정) | 코드로 산식 확인 ✅ |
| 16 보조 연결·96 오너·14,393B 누출 | profiles JSON 고정값 | 미측정 | 코드 확인 ✅ (값 자체는 프로파일 상수) |
| 크래시 트리거 ≈60 GiB | 코드 주석 + 재현문서 | **E0에서 측정 예정** | ⏳ |
| avx512f/vl 필수 (RCE) | 재현문서 셸 grep 권고뿐, **코드 검사 없음** | Mac(에뮬, avx512 없음)에서 E0 관측 예정 | 🆕 코드 검증 구멍 — H3/H4는 프로파일 상수(glibc 2.41 EVEX/YMM memcpy, arena offset)로 간접 고정 |
| "프레시 컨테이너에서만 안정" | README/재현문서 (16 동시 클라이언트 하 2회 실패) | P4 캐릭터라이징으로 반증/지지 예정 | ⏳ |
| 재현 성공 기록 (189-223s, 2026-11-06) | 재현문서 | 재현 불가능한 우리 환경 변수 존재 | 문서 주장 |
| 클린업 오버크레딧 → 윈도우 언더플로 수용 | 코드 오라클 + 주석 | 소스 diff 분할 대응 (deep-analysis) | 진행 중 |

## 4. 우리 랩 재현 관점 요약

1. **클라이언트도 Linux x86-64**: simple 트리거는 `libssl.so.3` dlopen + CPython 3.10 ssl 레이아웃 의존 →
   **클라이언트 컨테이너(python:3.10-slim, amd64)**에서 실행. streamer.c는 대상 호스트에서 재빌드.
2. **파라미터화 포인트**: `--target`(RCE)/위치인자(트리거)만. 인증서 무시(CERT_NONE). 타이밍 노브는
   코드 상수(0.05/0.1s 이벤트 루프 분리 등 — "재현성 민감, 마개조 금지" 권고).
3. **하드코딩(재프로파일링 대상)**: nginx 델타 3종(send_chain 139,856 / resolver_timeout -310,400 /
   destroy_pool -398,896), libc arena offset 2종, 힙 오프셋 다수, `/index.html` 896B 전제,
   PIE 캐노니컬 범위, 모듈 ctx 128슬롯 스캔.
4. **프로파일 교체 규칙**: 버전만 바꾼 프로파일 부족 — 네이티브 트레이스 재교정 필요 (profiles/README 공식 입장).
   우리 4-arm 랩은 소스 빌드라 Rapid7 공식 이미지(nginx:1.31.8 digest 고정, Debian 13/glibc 2.41)와
   다름 → **RCE 재현은 공식 이미지 그대로**, 우리 소스빌드 랩은 트리거/캐릭터라이징용으로 역할 분리. **[판단]**
5. **실행 절차**: 시도마다 컨테이너 restart(프레시 힙 절차적 강제) → 단발 실행 → 외부 오라클 → 실패 시 restart.

## 5. 남은 것

- E0: Mac 에뮬에서 simple 트리거 크래시 가부 (P2 전제 판정)
- P4: DFIRtx에서 RCE 전체 재현 + 성공률 episode 측정
- avx512 비의존 경로(I-b): 코드 검사가 없다는 점은 사실이나, EVEX/YMM memcpy가 누출·덮어쓰기의
  핵심이라 프로파일 재구성이 필요 → [미확인] 유지, I-b 실험에서 검증
