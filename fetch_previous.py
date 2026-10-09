"""No branch means no release yet; network/auth/other failures abort the build."""
import json
import os
from pathlib import Path
import subprocess
from build import download, REPOSITORY

if __name__ == "__main__":
    refs = subprocess.check_output(["git", "ls-remote", "--heads",
        f"https://github.com/{REPOSITORY}.git", "release"], text=True, timeout=60,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}).strip()
    if not refs:
        print("First publication; no previous release")
    else:
        commit = refs.split()[0]
        data = download(f"https://raw.githubusercontent.com/{REPOSITORY}/{commit}/manifest.json")
        json.loads(data)
        Path("previous").mkdir(exist_ok=True)
        Path("previous/manifest.json").write_bytes(data)
        print("Previous release: " + commit)
