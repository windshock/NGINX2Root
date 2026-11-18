# 취약점 분석 기준선 — NGINX2Root 5건 + 동반 5건 (F/P/H)

작성일: 2026-11-19 · 성격: 공개 자료 기반 기준선 (소스 실측은 deep-analysis로 이관)
근거 체계: 브리핑 문서 `../nginx2root_java4shell_comparison_2026-11-19.md`의 [R1]~[R12] 습계.
  [R1] Rapid7 블로그 · [R2] Rapid7 PoC 저장소/재현문서 · [R3] Xint NGINX2Root ·
  [R4] Wiz · [R5] nginx.org 릴리스 · [R6] Calif Java4Shell · [R7] CERT-EU ·
  [R8] 공식 권고 · [R9] Red Hat Java4Shell · [R10]-[R12] OpenJDK2Shell 자체 연구

> 표기: F=확정 사실(공개 1차 자료로 확인) · P=전제(미검증) · H=가설(우리가 검증할 것).
> 결론어는 확정/지지됨/미지지/관측불가 4종만. 소스 코드 확인 결과는 **실측(소스)** 로 표기.

## 1. CVE-2026-123007 — HTTP/2 흐름제어 정수 언더플로 → 힙 OOB (e2e 1순위)

### 확정 사실 (F)
- F1. HTTP/2 전송 윈도 계산의 정수 언더플로가 근본 원인. 힙 OOB read/write로 이어짐. [R1][R3]
- F2. 인증 불필요. 취약 빌드에서 HTTP/2가 켜져 있고 공격자가 NGINX h2 엔드포인트에
  도달하면 트리거 가능. 백엔드 앱 무관(정적 파일 서비스도 표면). [R1][R4]
- F3. Rapid7이 NGINX 1.31.8 / linux-amd64에서 worker 권한 RCE PoC 전체 공개
  (`simple-trigger-poc.py`, `exploit/exploit.py`, 독립 재현 문서). [R2]
- F4. 공개 RCE 실증의 조건: 새 Docker 컨테이너(신선 힙), 특정 glibc memcpy 경로,
  CPU avx512f+avx512vl, 약 119.02 GiB 전송, 16개 보조 연결을 통한 힙 그루밍,
  메모리 유출→ASLR 우회→요청 풀 콜백 조작. [R1][R2]
- F5. Wiz·Xint가 별도 RCE 실증 발표 (전체 코드 비공개). [R3][R4]
- F6. 수정: Stable 1.30.7 / Mainline 1.31.9. 취약 코드는 1.9.5~1.31.8에 존재. [R5]
- F7. HTTP/2 OFF가 직접 완화. [R3][R7]
- F8. CERT-EU 11/18 기준 실공격(in-the-wild) 보고 없음. [R7]

### 전제 (P — 미검증, deep-analysis/E0에서 검증)
- P1. 언더플로 지점은 `ngx_http_v2` 전송 윈도 차감 연산이고 size 계산 오류가
  원인이다 (정확한 함수·라인은 소스 diff로 확정 예정).
- P2. 크래시 트리거(~60 GiB급)는 avx512 불필요 — 언더플로/OOB 자체는 CPU 무관할 것.
  → Mac 에뮬에서도 크래시 가능할 것 (E0 판정 대상).
- P3. Rapid7 exploit.py의 하드코딩(주소·오프셋·프로파일)은 재파라미터화 가능 수준.

### 가설 (H — 본 연구의 검증 대상)
- H1. 4-arm에서 트리거 특이성: A1만 크래시, A2/A3/A4는 무해할 것이다.
- H2. 신선 컨테이너 N=10 episode 재현율은 유의미하게 높을 것이다 (Rapid7 주장 재검증).
- H3. 부하/오염 힙/대역폭 제한 조건에서 성공률은 유의하게 감소할 것이다.
- H4. 전송량·프로파일 개선 여지가 존재한다 (I-a/b/c 측정).

## 2. CVE-2026-123633 — HTTP/2 연결 draining 중 upstream 경합 UAF

- F1. 연결 정리(connection draining) 중 upstream 연결과의 경합 → UAF. [R3]
- F2. HTTP/2 + 백엔드 프록시 구성이 노출 조건. 인증 없는 RCE 경로 (연구팀 실증). [R3]
- F3. HTTP/2 OFF로 차단. 123007과 **독립적** 경로 (둘을 묶어야 RCE가 되는 것 아님). [R3][R4]
- F4. 전면 PoC 비공개 (Wiz 실증 발표만). [R4]
- P1. 경합 창은 요청 종료·연결 해제 순서에 있고, RST_STREAM/타임아웃 조합으로
  반복 가능한 확률창을 만들 수 있을 것이다. (트리거 개전 조건 — 미검증)
- H1. 자체 트리거로 A1(프록시 구성)에서 UAF 크래시를 재현할 수 있을 것이다.

## 3. CVE-2026-123634 — DNS resolver 대기 목록 순회 UAF

- F1. resolver 대기 목록(wait list) 순회 중 UAF. [R3]
- F2. 노출 조건: 요청값 기반 동적 `proxy_pass` + `resolver` + `mirror`/SSI 등
  **동시 서브리퀘스트**. [R3]
- F3. HTTP/2 OFF와 무관 (별도 경로). 인증 없는 RCE 경로 (연구팀 실증). [R3]
- F4. `mirror` 중지·고정 upstream이 완화 방향이나 전면 차단 아님. [R3]
- P1. DNS 응답 지연(타임아웃 직전 응답)으로 대기 목록 조작 타이밍을 만들 수 있을 것이다.
- H1. 자체 DNS 서버(지연 제어) + mirror 서브리퀘스트 조합으로 크래시 재현 가능할 것이다.

## 4. CVE-2026-121810 — HTTP/3(QUIC) 스트림·연결 종료 UAF

- F1. QUIC 스트림·연결 종료 처리 중 UAF. [R3]
- F2. HTTP/3 + upstream 프록시 및 특정 연결 자원 조건이 노출 요건. [R3]
- F3. HTTP/2 OFF로 안 막힘 — QUIC 리스너 제거(또는 http3 off) 필요. [R3]
- P1. 스트림 동시 다발 종료(스트림 ID 역순·즉시 close 조합)가 경합창을 넓힐 것이다.
- H1. aioquic 클라이언트로 종료 경합 크래시를 재현할 수 있을 것이다.

## 5. CVE-2026-113425 — Mail Proxy 인증 연결 처리 UAF

- F1. mail 모듈 인증 연결 처리 중 UAF. [R3]
- F2. 노출 조건: `mail {}` + `proxy on` + `auth_http`. [R3]
- F3. 인증 없는 RCE 경로 (연구팀 실증). 완화는 미신뢰 클라이언트 차단/기능 정지. [R3]
- P1. auth_http 백엔드 응답 지연·연결 끊김 조합이 경합 조건을 만들 것이다.
- H1. auth_http 시뮬레이터(지연 제어)로 인증 도중 경합 크래시를 재현할 수 있을 것이다.

## 6. 동반 5건 (방어 가이드 커버 — 상세 판정은 각 권고)

| CVE | 문제 (릴리스 노트 기준 [R5]) | 비고 |
|---|---|---|
| CVE-2026-118899 | TLS 1.3 클라이언트 요청 본문 수신 무한 루프 | DoS급 |
| CVE-2026-120993 | PROXY protocol v2 NULL 포인터 역참조 | DoS급 |
| CVE-2026-125283 | `alias`+`try_files` 버퍼 오버플로 | 조건·영향 개별 판정 |
| CVE-2026-120967 | `stream` 클라이언트 인증서 검증 SNI 우회 | 검증 우회 |
| CVE-2026-123640 | `stream ssl_preread` 불충분한 검증 | 검증 우회 |

## 7. NGINX2Root 체인 전체 구조 (방어 관점 요약)

```
[1단] NGINX CVE 5건 중 하나 → worker 권한 코드 실행 (본 연구 e2e 범위)
[2단] 별도 Linux 커널 SCTP LPE → 호스트 root/컨테이너 탈출 (Xint 시연 [R3])
      → 본 저장소는 문서·점검 항목만 다룸 (GOAL §1-5)
```

## 8. 우리 실측 우선순위 (RESEARCH-PLAN §2-5 대응)

1. 123007 diff 루트코즈 **실측(소스)** → deep-analysis (진행 중)
2. Rapid7 PoC 주장vs사실 → EXTERNAL-REVIEW (진행 중)
3. E0 Mac 크래시 가부 → P2 판정
4. H1~H4 → Phase 3/4 episode로 측정
