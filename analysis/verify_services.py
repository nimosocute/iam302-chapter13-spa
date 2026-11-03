"""Bounded, loopback-only Chapter 13 verification. One fixed echo marker."""
import json, socket, threading, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = Path(r'C:\Lab13Analysis\verify')
ROOT.mkdir(exist_ok=True)
def log(name, **fields):
    with (ROOT/name).open('a',encoding='utf-8') as out:
        out.write(json.dumps(dict(time=time.time(),**fields))+'\n')
class HTTP(BaseHTTPRequestHandler):
    def do_GET(self):
        log('http-o.jsonl',path=self.path,headers=dict(self.headers),response_hex='6f')
        self.send_response(200); self.send_header('Content-Length','1'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(b'o')
    def log_message(self,*_):pass
def tcp():
    with socket.socket() as s:
        s.bind(('127.0.0.1',8910));s.listen(1)
        while True:
            c,a=s.accept()
            with c:
                log('tcp8910.jsonl',event='accepted',peer=a)
                c.settimeout(.3);started=time.monotonic();sent=False
                with (ROOT/'lab03-verify-cipher.bin').open('ab') as f:
                    while time.monotonic()-started < 18:
                        if not sent and time.monotonic()-started > 2:
                            # Fixed benign command; no interactive command interface.
                            payload=b'BYPqdaDOSWKzO19YTXLLTmnHTC0M'
                            c.sendall(payload);log('tcp8910.jsonl',event='sent_fixed_echo',wire_ascii=payload.decode(),plaintext='echo LAB13_VERIFIED\\r\\n');sent=True
                        try:data=c.recv(65536)
                        except socket.timeout:continue
                        except ConnectionResetError:break
                        if not data:break
                        f.write(data);f.flush();log('tcp8910.jsonl',event='received',length=len(data),hex=data.hex())
                log('tcp8910.jsonl',event='session_end')
threading.Thread(target=tcp,daemon=True).start()
ThreadingHTTPServer(('127.0.0.1',80),HTTP).serve_forever()
