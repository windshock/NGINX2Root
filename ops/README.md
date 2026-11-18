# ops/ — 랩 인프라 · 계측 · 방어 운영

## 구성

| 경로 | 역할 |
|---|---|
| `docker/` | 4-arm 랩(compose) + CVE 노출 변형 + 헬퍼(slowback/dnssim/authsim/imapsim) |
| `run_local.sh` | 랩 up/verify/down/logs/crashes |
| `check_alpn.py` | ALPN h2 협상 검사 |
| `inventory.sh` | (P5) 자산 점검 — 버전/기능/노출 |
| `monitor.sh` | (P5) worker 크래시·자식 프로세스·캐너리 감시 |
| `mitigate.sh` | (P5) http2 off 등 완화 적용·검증 |
| `detect-rce.sh` | (P5) RCE 징후 탐지 (execve/아웃바운드) |
| `results/` | 관측 수집 로그 |

## 4-arm (RESEARCH-PLAN §3)

| Arm | 컨테이너 | 이미지 | 포트(호스트) | conf |
|---|---|---|---|---|
| A1 취약 | n2r-a1 | lab:1.31.8 | 8443 | h2on.conf |
| A2 패치 | n2r-a2 | lab:1.31.9 | 8444 | h2on.conf |
| A3 완화 | n2r-a3 | lab:1.31.8 | 8445 | h2off.conf |
| A4 대조 | n2r-a4 (+n2r-a4load) | lab:1.31.9 | 8446 | h2on.conf + 정상 부하 |

CVE 노출 변형: `--profile cve123633`(8447) / `cve123634`(8448) / `cve121810`(8449 tcp+udp) /
`cve113425`(8143). 디버그 변형: `--profile debug`(8543, worker 1개 + error debug).

## 기본 흐름

```bash
ops/run_local.sh up                 # core 4-arm 기동 (최초 빌드 수 분)
ops/run_local.sh verify             # 버전·ALPN(A1/A2/A4=h2, A3≠h2)·페이지 검증
# ... exploit/ 트리거 실행 ...
ops/run_local.sh crashes            # worker crash/코어덤프 확인
ops/run_local.sh down
```

## 계측 (RESEARCH-PLAN §1-2)

- 모든 arm: `h2_hunt` access 포맷(conn, requests, proto, request_length, bytes_sent)
- 코어덤프: compose `ulimits core:-1` + `worker_rlimit_core unlimited` + `working_directory /cores`
  → `docker exec n2r-a1 ls /cores` 또는 named volume `nginx2root-lab_cores`
- 크래시 원인 태깅: error.log의 `signal 11`·`exited on signal` 라인과 동시간대
  access/h2_hunt·`ss` 샘플 3축 상관 (계측 비판 #2)
- e2e 프로파일 주의: debug 로깅은 할당 패턴을 바꾼다 — 풀 RCE 재현엔 `h2on.conf`(notice) 사용

## 주의

- 컨테이너/인증서는 랩 전용 자가서명. 코드 실행 실증은 캐너리(`exploit/payloads/`)만.
- cve121810(quic)은 trixie 빌드(OpenSSL 3.5+) — bookworm로 빌드하면 QUIC 핸드셰이크 불완전 가능.
- 이 랩은 인터넷에 노출 금지 (127.0.0.1 바인딩이라도 운영망에서는 격리 필수).
