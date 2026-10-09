"""Install a pinned official Mihomo release, checking the release asset digest."""
import gzip
import hashlib
import io
import os
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = "v1.19.32"
ASSETS = {
    "Linux": (f"mihomo-linux-amd64-compatible-{VERSION}.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"),
    "Windows": (f"mihomo-windows-amd64-compatible-{VERSION}.zip", "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
}

if __name__ == "__main__":
    if platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("Installer supports amd64 only; supply your own verified Mihomo for other architectures")
    name, digest = ASSETS[platform.system()]
    with urllib.request.urlopen(f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{name}", timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit("Mihomo asset checksum mismatch")
    target = Path("runtime") / ("mihomo.exe" if platform.system() == "Windows" else "mihomo")
    target.parent.mkdir(exist_ok=True)
    if platform.system() == "Windows":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binaries = [n for n in archive.namelist() if n.endswith(".exe")]
            if len(binaries) != 1:
                raise SystemExit("Unexpected archive layout")
            target.write_bytes(archive.read(binaries[0]))
    else:
        target.write_bytes(gzip.decompress(data))
        os.chmod(target, 0o755)
    print(f"Verified Mihomo {VERSION}: {target}")
