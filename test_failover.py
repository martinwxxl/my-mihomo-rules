"""Offline end-to-end primary -> backup -> primary test with local HTTP proxies."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import yaml
from build import make_config


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(core, region="美国"):
    states = {"primary": True, "backup": True}
    servers = []
    for airport in states:
        def handler(name):
            class Proxy(BaseHTTPRequestHandler):
                def do_CONNECT(self):
                    if not states[name]:
                        self.send_response(503)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.end_headers()
                    self.connection.settimeout(3)
                    request = self.rfile.readline()
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    health = b"/health" in request
                    body = b"" if health else name.encode()
                    status = b"204 No Content" if health else b"200 OK"
                    self.wfile.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: " + str(len(body)).encode()
                                     + b"\r\nConnection: close\r\n\r\n" + body)
                    self.wfile.flush()
                    self.close_connection = True
                def do_GET(self):
                    if not states[name]:
                        self.send_response(503)
                        self.end_headers()
                        return
                    health = "/health" in self.path
                    body = b"" if health else name.encode()
                    self.send_response(204 if health else 200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                def log_message(self, *args):
                    pass
            return Proxy
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(airport))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append((airport, server))
    control, mixed = free_port(), free_port()
    url = "http://health.invalid/health"
    cfg = make_config({}, ["ai"], "yaml")
    cfg.update({"mixed-port": mixed, "allow-lan": False, "external-controller": f"127.0.0.1:{control}",
           "hosts": {"health.invalid": "198.51.100.1", "content.invalid": "198.51.100.1"},
           "secret": "offline-test", "log-level": "warning", "dns": {"enable": False},
           "rule-providers": {}, "rules": ["MATCH,人工智能"]})
    for group in cfg["proxy-groups"]:
        if group["type"] in ("url-test", "fallback", "load-balance"):
            group.update({"url": url, "interval": 1, "timeout": 500})
    with tempfile.TemporaryDirectory(prefix="mihomo-failover-") as temporary:
        path = Path(temporary)
        for airport, server in servers:
            file = path / (airport + ".yaml")
            file.write_text(yaml.safe_dump({"proxies": [{"name": airport + "-node " + region, "type": "http",
                "server": "127.0.0.1", "port": server.server_port}]}), encoding="utf-8")
            cfg["proxy-providers"][airport] = {"type": "file", "path": str(file), "health-check":
                {"enable": True, "url": url, "interval": 1, "timeout": 500, "lazy": False, "expected-status": 204}}
        file = path / "config.yaml"
        file.write_text(yaml.safe_dump(cfg), encoding="utf-8")
        with (path / "log.txt").open("w") as log:
            process = subprocess.Popen([core, "-d", str(path), "-f", str(file)], stdout=log, stderr=log)
            try:
                direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                # Explicit proxy is applied to a non-local target so no_proxy cannot bypass it.
                proxied = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{mixed}"}))
                def expect(airport):
                    end = time.monotonic() + 20
                    while time.monotonic() < end:
                        if process.poll() is not None:
                            raise AssertionError((path / "log.txt").read_text())
                        try:
                            for name in states:
                                req = urllib.request.Request(f"http://127.0.0.1:{control}/providers/proxies/{name}/healthcheck",
                                    headers={"Authorization": "Bearer offline-test"})
                                direct.open(req, timeout=2).close()
                            with proxied.open("http://content.invalid/content", timeout=2) as response:
                                actual = response.read().decode()
                            if actual == airport:
                                print("Verified " + region + " nodes: traffic through " + airport)
                                return
                        except (OSError, ValueError):
                            pass
                        time.sleep(0.3)
                    raise AssertionError("Failover did not select " + airport + "\n" + (path / "log.txt").read_text())
                expect("primary")
                states["primary"] = False
                expect("backup")
                states["primary"] = True
                expect("primary")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                for _, server in servers:
                    server.shutdown()
                    server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--region", default="美国")
    args = parser.parse_args()
    run(str(Path(args.mihomo).resolve()), args.region)
