# CORRECTION-1 — 방어 가이드의 근거 범위와 운영 판정 정정

작성일: 2026-11-19 · 대상: DEFENDER-GUIDE v1 및 기존 작업 트리의 트래픽 보강 내용

기존 실험·원시 파일은 보존한다. [README](README.md)의 정정 원칙에 따라 일반화·측정
범위 해석의 정정 이력을 남기고 운영 지침은 [최신 방어자 가이드](DEFENDER-GUIDE.md)에
반영했다. 기존 RCE/크래시 에피소드의 판정을 취소하는 내용은 아니다.

| 기존 표현/판단 | 정정 | 근거·영향 |
|---|---|---|
| RCE 성공 시 worker의 execve와 산출물이 반드시 남음 | 랩의 system()+캐너리 경로 결과에 한정. 모든 RCE의 필수 흔적이 아님 | [ep01 JSON](exploit/results/CVE-2026-123007/a1-dfirtx/ep01-rce/attempt_01.json)은 파일·소유자 요약이며 exec 감사 기록은 아님. 자식/파일 부재로 비침해 판단 금지 |
| worker 자식은 RCE 성공 증거이며 정상 실행은 없음 | 조사 신호이며 모듈/업무 기준선과 계보·시각·다른 증거 확인 필요 | OpenResty/외부 실행 모듈 고려. UID 필터만으로 nginx 자식·특정 CVE 식별 불가 |
| ep06 RX 119.9GB/TX 0.43GB는 공격 연결 전송량·패턴을 직접 측정 | pod eth0 한 시점 누적값에 한정 | [스냅샷](exploit/results/CVE-2026-123007/a1-dfirtx/ep06-rce/live_traffic_snapshot.txt)에 시작값·구간·연결별 분리 근거 없음. RX/TX=276.57은 재계산 가능하나 속도·공격 귀속은 별개 |
| 277:1은 정상 다운로드와 반대이므로 오인 가능성이 낮음 | 정상 업로드·수집 API도 수신 우세. A4 비교 전 오탐률 관측불가 | 정상 다운로드만 비교하면 편향. 임계값으로 배포하지 않고 복합 신호 조사에 사용 |
| 119GB가 소수 로그 행으로 남음을 실측 확인 | 스냅샷은 해석 요약이며 대응 access.log 원본·구간 집계가 없음 | 제어 프레임 전체가 request_length에 반영되지 않는 것은 소스·변수 정의로 설명. 수치의 로그 대조 실측과 구별 |
| 119.02GiB/약294초는 약3.3Gbit/s, 1Gbps에서는 시간이 늘어날 뿐 성립 | ep01 293.71초 기준 평문 평균 약3.48Gbit/s, 1Gbit/s 산술 하한 약17분 | [상황 보고 §9](ESCALATION-STATUS-2026-11-19.md). 연결 수명·중간 장비 등으로 성공 여부는 별도 조건 |
| ss의 bytes_established로 회계 | bytes_received/bytes_sent 등 실제 제공값·계층 확인 | 필드·권한 차이와 NIC/TCP/평문 측정값 차이를 구별 |
| mitigate.sh off/verify로 적용·검증 완료 | 설정 전체·실제 바이너리/설정 경로·SNI·정상 대조 연결 독립 확인 | 지정 파일만 수정, -c 미전달, ALPN 정보 없음도 OK 가능. 도구는 이번 문서 작업에서 수정하지 않음 |
| detect-rce.sh의 worker 자식 검색 신뢰 | worker PID 대신 PPID로 검색하는 오류 명시 | [스크립트](ops/detect-rce.sh) 코드 확인. 음성 출력을 비침해 근거로 사용 금지 |
| flow-control 메시지를 일반 에러 로그에서 탐지 | 해당 소스에서 NGX_LOG_INFO. notice 이상에서는 보이지 않을 수 있음 | 1.31.8/1.31.9 ngx_http_v2_state_window_update() 확인. 악용의 필요·충분조건 아님 |
| 수정 버전 미만을 동일 조건으로 선별 | CVE별 시작 버전·수정 브랜치·백포트·기능 구별 | [공식 목록](https://nginx.org/en/security_advisories.html). 120993은 1.31.4~1.31.8, 1.31.9 수정 |

검증: 기존 가이드·작업 트리 diff, 운영 스크립트, 소스 두 태그, episode JSON 10건·원시
실행 로그·스냅샷을 읽고 수치를 재계산했다. 공식 보안 목록·릴리스·모듈 문서와 교차 확인했다.
새 공격 실험·운영 설정 변경·원격 배포는 수행하지 않았다.
