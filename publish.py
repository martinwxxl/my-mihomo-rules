"""Publish validated dist in one fast-forward ref update; never force push."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def verify_dist(dist):
    allowed = {"LICENSE", "NOTICE.md", "README.md", "manifest.json", "conflicts.json",
               "SHA256SUMS", "openclash-yaml.yaml", "openclash-mrs.yaml",
               "LICENSE-Pro_cn.txt", "NOTICE-Pro_cn.md"}
    expected = {}
    for line in (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Unsafe artifact path")
        expected[name] = digest
    actual = set()
    for path in dist.rglob("*"):
        if path.is_symlink():
            raise ValueError("Symlink in artifact")
        if not path.is_file():
            continue
        name = path.relative_to(dist).as_posix()
        if not (name in allowed or (name.startswith("rules/") and len(Path(name).parts) == 2
                                   and path.suffix in (".yaml", ".mrs"))):
            raise ValueError(f"Unexpected artifact: {name}")
        if name != "SHA256SUMS":
            actual.add(name)
            if expected.get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
                raise ValueError(f"Checksum mismatch: {name}")
    if actual != set(expected) or not allowed.issubset(actual | {"SHA256SUMS"}):
        raise ValueError("Incomplete artifact")


if __name__ == "__main__":
    dist = Path("dist").resolve()
    verify_dist(dist)
    repository = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GITHUB_TOKEN"]
    # Credentials are passed in environment, never command arguments or remote URL.
    import base64
    env = os.environ.copy()
    env.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                "GIT_CONFIG_VALUE_0": "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + token).encode()).decode(),
                "GIT_TERMINAL_PROMPT": "0"})
    with tempfile.TemporaryDirectory(prefix="mihomo-publish-") as temporary:
        path = Path(temporary)
        def git(*args, **kwargs):
            return subprocess.run(["git", *args], cwd=path, env=env, check=True, **kwargs)
        git("init", "-b", "release")
        git("remote", "add", "origin", f"https://github.com/{repository}.git")
        refs = git("ls-remote", "--heads", "origin", "release", capture_output=True, text=True).stdout.strip()
        if refs:
            git("fetch", "--depth=1", "origin", "release")
            git("checkout", "-B", "release", "FETCH_HEAD")
            git("rm", "-r", "--ignore-unmatch", ".", stdout=subprocess.DEVNULL)
        for source in dist.iterdir():
            if source.is_dir():
                shutil.copytree(source, path / source.name)
            else:
                shutil.copyfile(source, path / source.name)
        git("config", "user.name", "github-actions[bot]")
        git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git("add", ".")
        changed = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=path, env=env).returncode
        if changed:
            git("commit", "-m", "Publish validated rules from " + os.environ["GITHUB_SHA"])
            git("push", "origin", "HEAD:refs/heads/release")
        else:
            print("Release already up to date")
