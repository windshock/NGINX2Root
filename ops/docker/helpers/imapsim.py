#!/usr/bin/env python3
"""imapsim — 최소 IMAP4rev1 백엔드 (mail 변형의 Auth-Server 프록시 종점).

인사말 후 모든 명령에 TAG OK로 응답하는 최소 서버. 프록시 경로 완결용.
의존성 없음.
"""
import socketserver


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"* OK imapsim ready\r\n")
        self.wfile.flush()
        tag = b"*"
        while True:
            line = self.rfile.readline()
            if not line:
                break
            parts = line.split()
            if parts:
                tag = parts[0]
            self.wfile.write(b"%s OK done\r\n" % tag)
            self.wfile.flush()
            print("[imapsim] %r" % line, flush=True)


class Srv(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    srv = Srv(("0.0.0.0", 1143), Handler)
    print("[imapsim] listening :1143", flush=True)
    srv.serve_forever()
