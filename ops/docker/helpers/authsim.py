#!/usr/bin/env python3
"""authsim — nginx mail auth_http 프로토콜 시뮬레이터 (CVE-2026-113425 경합용).

nginx mail 프록시는 클라이언트 인증 시 auth_http에 GET /auth?... 를 보내고
응답 헤더(Auth-Status/Auth-Server/Auth-Port)로 프록시 대상을 결정한다.

엔드포인트:
  /auth?delay=N   N ms 지연 후 Auth-Status: OK + Auth-Server: imapsim:1143
  /auth?nx        지연 없이 Auth-Status: Invalid (인증 거부 경로)
경합 창: delay로 "인증 응답 대기 중 클라이언트 연결 끊김" 상태를 만든다.
의존성 없음.
"""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        # nginx가 보낸 Auth-Protocol/Auth-User 등 요청 라인이 관측 포인트
        print("[authsim] %s %s" % (self.address_string(), self.path), flush=True)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        delay = float(q.get("delay", ["0"])[0]) / 1000.0
        if delay:
            time.sleep(delay)
        if "nx" in q:
            body = b"invalid"
            self.send_response(200)
            self.send_header("Auth-Status", "Invalid")
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Auth-Status", "OK")
            self.send_header("Auth-Server", "imapsim")
            self.send_header("Auth-Port", "1143")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)
    print("[authsim] listening :9000", flush=True)
    srv.serve_forever()
