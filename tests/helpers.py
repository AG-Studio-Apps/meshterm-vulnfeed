"""Test helpers: throwaway minisign keys and a scratch copy of the repository layout."""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for sub in ("builder", "scripts", "alert"):
    path = os.path.join(ROOT, sub)
    if path not in sys.path:
        sys.path.insert(0, path)

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def make_key(directory, name):
    """A passwordless throwaway pair: (secret key path, public key path)."""
    sec, pub = os.path.join(directory, f"{name}.key"), os.path.join(directory, f"{name}.pub")
    subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec], check=True, capture_output=True)
    return sec, pub


def make_keys_dir(directory, feed_pub, emergency_pub=None):
    keys = os.path.join(directory, "keys")
    os.makedirs(keys, exist_ok=True)
    shutil.copy(feed_pub, os.path.join(keys, "vulnfeed-feed.pub"))
    if emergency_pub:
        shutil.copy(emergency_pub, os.path.join(keys, "vulnfeed-emergency.pub"))
    return keys


def scratch_repo():
    """A temp dir with curated/ copied from the real repository and an empty builds/."""
    tmp = tempfile.mkdtemp(prefix="vulnfeed-test-")
    shutil.copytree(os.path.join(ROOT, "curated"), os.path.join(tmp, "curated"))
    os.makedirs(os.path.join(tmp, "builds"))
    return tmp


def no_releases():
    """ReleaseOptions whose S2 step builds nothing (curated-only, no network)."""
    import build
    return build.ReleaseOptions(builder=lambda site_v1, log, previous: ({}, {}))


FAKE_SOURCES = {"osv": {"Debian": "2026-11-05T13:03:11Z"},
                "archive": {"bookworm": "2026-07-11T10:16:37Z", "bookworm-security": "2026-11-05T14:52:30Z"},
                "baseline": {"debian-12": "2023-06-10"}}


def fake_releases(seen=None):
    """ReleaseOptions whose S2 step writes one small, valid debian-12 file (no network). `seen` collects the
    `previous` argument of each call."""
    import build
    import osvfeed
    from feedlib import content_name, sha256_hex

    def builder(site_v1, log, previous):
        if seen is not None:
            seen.append(previous)
        release = next(r for r in osvfeed.RELEASES if r.key == "debian-12")
        rows = [{"source": "apt", "introduced": "0", "fixed": "2.6.2", "severity": 3, "ids": ["CVE-2026-109518"],
                 "kernel": False, "date": "2026-11-04"},
                {"source": "linux", "introduced": "0", "fixed": "6.1.158-1", "severity": 4,
                 "ids": ["CVE-2026-1", "CVE-2026-2"], "kernel": True, "date": "2026-10-30"}]
        data = osvfeed.body_bytes(osvfeed.release_body(release, rows))
        name = "r/" + content_name("debian-12", data)
        os.makedirs(os.path.join(site_v1, "r"), exist_ok=True)
        with open(os.path.join(site_v1, name), "wb") as handle:
            handle.write(data)
        return ({"debian-12": {"format": "dpkg", "file": name, "sha256": sha256_hex(data), "bytes": len(data),
                               "rows": 2}}, dict(FAKE_SOURCES))
    return build.ReleaseOptions(builder=builder)
