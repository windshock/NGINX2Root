#!/usr/bin/env python3
"""slowback — 경합 조건 조절용 지연 HTTP 백엔드 (123633/121810 변형의 upstream).

엔드포인트:
  /slow?ms=N   N ms 지연 후 200 (기본 1000)
  /hang        장기 미응답 (연결 draining 중 upstream 잔존 유도)
  /            즉시 200
의존성 없음. 표준 라이브러리만 사용.
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[slowback] %s - %s" % (self.address_string(), fmt % args), flush=True)

    def _reply(self, body=b"ok\n"):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/slow":
            ms = int(q.get("ms", ["1000"])[0])
            time.sleep(ms / 1000.0)
            self._reply(("slow %d\n" % ms).encode())
        elif u.path == "/hang":
            # 읽기 타임아웃 없이 장기 대기 — 프로세스 종료까지
            time.sleep(3600)
        else:
            self._reply()


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    print("[slowback] listening :8080", flush=True)
    srv.serve_forever()
