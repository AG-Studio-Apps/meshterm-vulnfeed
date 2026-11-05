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
