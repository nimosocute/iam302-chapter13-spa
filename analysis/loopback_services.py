"""Local lab observation: HTTP replies plus passive TCP collection, no commands."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(r"C:\Lab13Analysis\artifacts")
ROOT.mkdir(exist_ok=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with (ROOT / "http-observed.jsonl").open("a", encoding="utf-8") as out:
            out.write(json.dumps({"time": time.time(), "path": self.path,
                                  "headers": dict(self.headers)}) + "\n")
        body = b"lab13-local-observation"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def passive_tcp():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 8910))
        server.listen()
        while True:
            client, address = server.accept()
            with client:
                client.settimeout(20)
                with (ROOT / "lab03-received.bin").open("ab") as out:
                    while True:
                        try:
                            data = client.recv(65536)
                        except (TimeoutError, ConnectionResetError):
                            break
                        if not data:
                            break
                        out.write(data)
                        out.flush()


threading.Thread(target=passive_tcp, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", 80), Handler).serve_forever()
