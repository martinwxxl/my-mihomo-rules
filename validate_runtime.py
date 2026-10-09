"""Start Mihomo and require every YAML/MRS provider to load, not only parse."""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
import yaml


def validate_runtime(core, directory, cfg):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    cfg = dict(cfg)
    cfg.update({"mixed-port": 0, "allow-lan": False, "dns": {"enable": False},
                "external-controller": f"127.0.0.1:{port}", "secret": secrets.token_hex(24)})
    file = Path(directory) / "runtime.yaml"
    file.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
    log = Path(directory) / "runtime.log"
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen([core, "-d", str(directory), "-f", str(file)],
                                   stdout=output, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 45
            last = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError("Mihomo exited while loading providers: " + log.read_text(encoding="utf-8"))
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{port}/providers/rules",
                        headers={"Authorization": "Bearer " + cfg["secret"]})
                    with urllib.request.urlopen(req, timeout=2) as response:
                        last = json.load(response)["providers"]
                    expected = cfg["rule-providers"]
                    if set(last) == set(expected) and all(last[name].get("ruleCount", 0) > 0 for name in expected):
                        print("Runtime loaded " + str(len(expected)) + " rule providers (all nonempty)")
                        return
                except (urllib.error.URLError, TimeoutError):
                    pass
                time.sleep(0.25)
            raise ValueError("Rule providers did not load: " + repr(last) + "\n" + log.read_text(encoding="utf-8"))
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
