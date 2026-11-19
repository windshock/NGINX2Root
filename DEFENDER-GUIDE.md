# 방어자 가이드 — NGINX2Root (2026-11-18 NGINX 보안 릴리스) 대응 (v1)

작성일: 2026-11-19 · 갱신: 2026-11-19 (v1 — 1차 세션) · 대상: 인프라·SOC·서비스 담당
근거: NGINX 공식 릴리스/권고 [R5][R8] · Rapid7 [R1][R2] · Xint [R3] · Wiz [R4] · CERT-EU [R7] ·
**본 저장소 소스 diff 실측** (`deep-analysis-CVE-*.md`) · 랩 실측 (`ops/`, 결과에 따라 갱신)

> 이 가이드의 탐지·완화 항목은 가능하면 **우리 4-arm 랩(A1 취약/A2 패치/A3 완화/A4 대조)에서
> 실측 근거**를 붙였다. 근거 없는 항목은 [미검증]으로 명시하고 실험(E0/episode) 후 갱신한다.

## 0. 가장 중요한 한 가지

**수정 버전(Stable 1.30.7 / Mainline 1.31.9)이 아니고 HTTP/2가 켜져 있으며 외부에서 도달
가능한 NGINX가 취약 자산이다.** CVE-2026-123007은 인증·백엔드 앱·특수 설정 없이 HTTP/2
흐름제어 회계 버그만으로 worker 권한 코드 실행까지 이어질 수 있고(공개 RCE PoC 존재 [R2]),
**정적 파일만 제공해도 표면이 된다** [R4]. 본 저장소 소스 실측으로 루트코즈 확정:
큐 대기 바이트가 WINDOW_UPDATE 검증에서 누락 → 커넥션 윈도 > 2^31-1 → size_t 언더플로로
검증 붕괴 → 부호 반전 → 버퍼 랩 → OOB read/write (`deep-analysis-CVE-2026-123007.md`).

| 취약점 클래스 | 크래시 | worker 자식프로세스 | 진입 조건 | 임시 완화 |
|---|---|---|---|---|
| **123007 (h2 윈도)** | 실패 시 SIGSEGV | 성공 시 있음 | **HTTP/2 ON + 도달성** (인증 불요) | **HTTP/2 OFF** |
| 123633 (h2 drain UAF) | 가능 | 성공 시 있음 | HTTP/2 + 프록시 + 커넥션 고갈 | **HTTP/2 OFF** |
| 123634 (resolver UAF) | 가능 | 성공 시 있음 | 동적 proxy_pass + resolver + 서브리퀘스트 | 구성 제거 (h2 OFF 무효) |
| 121810 (QUIC UAF) | 가능 | 성공 시 있음 | HTTP/3 + 커넥션 고갈 | **QUIC 리스너 제거** |
| 113425 (mail UAF) | 가능 | 성공 시 있음 | mail 프록시 + auth_http | 메일 포트 통제 |

## 1. 자산 식별 (inventory.sh 연동)

```bash
bash ops/inventory.sh            # 호스트 nginx
bash ops/inventory.sh --docker   # 소스 빌드/컨테이너 계열
```

판정 순서 (브리핑 §6 습계, 본 저장소 실측 보강):
1. **정확한 패치 포함 여부**: `nginx -v`만으로 판정 금지 — 배포판 백포트(패키지 버전)와
   제품 내장 바이너리(OpenResty·Ingress·어플라이언스)는 별도 확인 [R5][R8]
2. **기능 활성**: `nginx -T`에서 `listen … http2|quic`, `http2 on`, `resolver`, `mirror`,
   `auth_http`, `mail` — 본 가이드 대상 5건의 노출 축
3. **도달성**: 원본 직접 도달(원본 우회, 내부망 경유) 가능성. CDN 경유는 종단 프로토콜 확인
4. **잔존 프로세스**: 이미지 교체 후에도 구 프로세스/구 digest 컨테이너 실행 여부

영향 버전 요약 (실측: 소스 태그 범위 + changes.xml):
- 123007/123633/123634/121810/113425: **1.31.9 미만 mainline / 1.30.7 미만 stable** 수정
  (취약 코드 존재 기간은 CVE별 상이 — 123007은 1.9.5~1.31.8 [R5])

## 2. 노출면 축소 — 즉시 (mitigate.sh)

패치 전 임시 완화의 유효 범위를 정확히:

| 조치 | 막는 CVE | 안 막는 CVE |
|---|---|---|
| `http2 off` (또는 listen에서 http2 제거) | **123007, 123633** | 123634·121810·113425 (h2 무관) |
| QUIC 리스너 제거 + UDP/443 차단 | **121810** | 나머지 전부 |
| 고정 upstream + mirror 제거 | **123634** (노출 축소, 전면 아님) | — |
| mail 포트를 인가 대역만 허용 | **113425** (노출 축소) | — |

```bash
bash ops/mitigate.sh check                 # 현재 상태
bash ops/mitigate.sh off /etc/nginx/nginx.conf   # http2 off 적용 + reload
bash ops/mitigate.sh verify ORIGIN:443     # ALPN h2 미협상 확인
```

**랩 실측**: A3(1.31.8 + h2 off)에서 ALPN이 http/1.1로만 협상됨을 확인(2026-11-19, ops/check_alpn.py).
운영 주의 3가지 [R3]:
- 같은 IP:포트를 공유하는 **모든 server 블록**에 적용되었는지 확인
- reload 후에도 **기존 h2 연결이 옛 worker에 잔존** 가능 → 필요 시 안내 후 restart
- gRPC/HTTP/2 전용 클라이언트 서비스 영향 사전 시험

CDN/WAF 프런트가 있다면: 외부 h2를 프런트에서 **완전 종단**하고 원본에는 HTTP/1.1로만
전달하며, **원본 직접 접근(우회) 경로를 차단**한 경우에만 완화로 성립. h2 프레임이 원본에
그대로 전달되는 구성(passthrough)이면 무효 [R3][R4].

## 3. 탐지 (detect-rce.sh / monitor.sh 연동)

### 3-A. NGINX worker 자식 프로세스 — RCE 성공의 가장 강력한 증거
```bash
# auditd (호스트, nginx 실행계정 euid로 조정)
-a always,exit -F arch=b64 -S execve -F euid=101 -k nginx_child
# 또는 EDR에서 nginx worker PID의 자식 execve 트리거
```
정상 운영에서 nginx worker가 `/bin/sh`·`curl`·`touch` 등을 실행할 일은 없다.
부모-자식 UID·PID 확인 후 알림.
**[랩 실측 확정 2026-11-19]**: 본 저장소의 e2e 재현(DFIRtx, 공개 PoC 체인 + 무해 캐너리)에서
`system()` 실행 결과가 **worker 실행계정(공식 이미지 uid:gid=101:101) 소유 파일**로 관측됨 —
`exploit/results/CVE-2026-123007/a1-dfirtx/ep01-rce/`. 즉 RCE 성공 시 worker 계정이
execve한 프로세스와 그 산출물이 반드시 남는다 → 3-A는 이론 근거가 아니라 **재현된 사실**.
(실패한 익스플로잇 시도는 자식 프로세스 없이 크래시만 남김 — 3-D 참조)

### 3-B. 이상 h2 연결 통계 — 트리거/그루밍 정황 (다중 신호 상관용)
트리거 특성(본 저장소 PoC 분석 기반, EXTERNAL-REVIEW):
- **수신 ≫ 응답**: 클라이언트→서버 약 60 GiB(트리거)/119 GiB(RCE), 서버→클라이언트 수 MiB
- 장시간(수 분~수 시간) 지속 + 단일 연결에서 **소형 WINDOW_UPDATE 폭탄**(13B 프레임 연속)
- 동일 IP의 **보조 연결 16개** (RCE 힙 그루밍 단계)
- access.log의 `request_length`는 제어 프레임을 못 세므로, `ss -tinp` bytes_established와
  h2_hunt 포맷(`$connection_requests`, `$bytes_sent`)의 교차 확인 필요
[미검증: A4 대조군 부하와의 분리 임계값은 P4 캐릭터라이징 후 제시 — 단일 신호 단정 금지]

### 3-C. 프로토콜 이상 징후
- 공격 전 단계에서 과도 WINDOW_UPDATE 누적 시 `client violated connection flow control`
  에러 로그 가능(정상 대량전송에서도 발생 — 보조 신호)
- 회계 파괴 자체는 **무로그** — 3-B/3-D와의 상관 없이는 관측 불가
- 123634의 1.31.8 흔적: `"could not cancel … resolving"` **ALERT** (본 저장소 실측:
  패치본에서 debug 강등됨) — 운영 로그에서 이 ALERT가 보이면 해당 경로 노출 의심

### 3-D. 크래시·코어덤프
```bash
docker logs <c> 2>&1 | grep -E 'worker process [0-9]+ exited on signal 11'
# 호스트: error.log 동일 패턴 + coredumpctl
```
크래시 단독 = 공격 시도의 가능한 정황 (GC/oom/모듈 버그 등 대체 원인 배제 필요).
**동시간대 3-B 패턴 상관 시에만 공격 시도로 판정** [R3][R7].

## 4. 완화 우선순위 (★ = root-cause 직접 차단)

1. ★ **패치**: 1.30.7/1.31.9 이상(또는 배포판 백포트) + 프로세스 재기동 — 근본 해결
2. ★ **HTTP/2 OFF** (패치 지연 시): 123007·123633 두 RCE 경로 직접 차단
3. QUIC 리스너 제거(사용하지 않을 때): 121810
4. 동적 resolver + mirror 구성 제거/고정 upstream: 123634 노출 축소
5. mail 프록시 포트 인가 통제: 113425 노출 축소
6. (참고) 속도 제한·연결 수 제한은 **공개 PoC의 효율을 낮추는 저항일 뿐 취약점을 수정하지
   않는다** — 정상 대용량 트래픽 오탐 위험과 함께 문서화만 권장 [R1][R3]

## 5. 패치 적용

```bash
nginx -v                        # 현재 버전
# 배포판: dpkg -l | grep nginx / rpm -q nginx  (백포트 여부)
# 적용 후: 프로세스 재기동 + §2 체크리스트로 잔존 h2/구 프로세스 확인
```
컨테이너: 이미지 digest 고정 갱신 + **구 digest 이미지로 돌아가는 파드/서비스 없는지** 확인.
NGINX Plus: 37.0.8.1 / 37.3.0.1 계열 [R8]. Ingress/OpenResty 등 내장 사례는 벤더 권고 확인.

## 6. 침해 의심 시 (IR 플레이북)

1. **격리**: 해당 NGINX 트래픽 차단(우회 경로 포함). 메모리 포렌식 필요 시 크래시 타이밍이
   중요하므로 즉시 재부팅하지 말고 코어덤프·`/cores`·컨테이너 상태 먼저 확보
2. **증거 고정**: error.log(전체), access.log(h2_hunt 포맷 포함), 코어덤프, 컨테이너 이미지
   digest, `ps`/`ss` 스냅샷, auditd nginx_child 이벤트
3. **판정 분리** (GOAL 원칙 습계): ① 크래시 ② 코드 실행 ③ 권한 상승(SCTP LPE)을 **별도
   단계로 기록** — 크래시만으로 "RCE 확정" 금지. worker 자식 프로세스+캐너리/마커 파일이
   실행의 직접 증거
4. **범위 확장 점검**: worker 권한 획득 후 (a) 컨테이너 탈출 시도(SCTP LPE [R3]) (b) 내부망
   횡적 이동 (c) 자료 유출 — 아웃바운드 로그 상관
5. **복구**: 패치 버전 재배포 + §2 완화 잔존 여부 재점검 + 인증서/시크릿 교체 평가
   (worker 메모리 노출 가능성)

## 7. 한계 (정직)

- 본 가이드의 탐지 임계값(3-B)은 아직 **정상 부하 대조군(A4)과의 정량 분리 전**이다 —
  P4 캐릭터라이징 완료 전까지 "정황 점수"로만 사용
- "공개 PoC가 내 서버에서 안 돌아감"은 안전 근거가 아니다 — 취약 빌드/기능/도달성 3요소로
  판정 [브리핑 최종 판단 습계]
- Rapid7 공개 RCE는 특정 프로파일(glibc 2.41, avx512f/vl, 프레시 힙) 대상이나, **다른 경로의
  실증(Xint·Wiz)도 존재**하므로 CPU/라이브러리 조건을 안전 근거로 쓰면 안 됨 [R3][R4]
- 2026-11-19 기준 실공격(in-the-wild) 보고 없음 [R7] — 그러나 공개 PoC 존재 + 다국어 설명
  확산 시 랜섬웨어·초기 침투 벡터화 가능성은 상존. 판정은 최신 위협情报로 갱신할 것
- 커널 SCTP LPE 체인은 본 가이드에서 점검 항목(`modprobe.d`의 `install sctp /bin/false` 등,
  단 로드 억제일 뿐)으로만 다룬다 — 커널 업데이트가 근본 [R3]
