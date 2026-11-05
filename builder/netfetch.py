"""Downloads for the S2 builder, with an on-disk cache that works with actions/cache. Python 3 stdlib only.

Cache layout (under --cache, default `cache/`):

    osv/<Ecosystem>/all.zip       the OSV bulk export
    osv/<Ecosystem>/state.json    {"highwater": newest `modified` seen in that zip, "etag": ..., "bytes": N}
    archive/by-hash/<algo>-<hex>  Sources.xz files, named by the SHA256 (or, where a Release file lists only
                                  that, SHA512) their Release file gives

all.zip is re-downloaded only when modified_id.csv names a change newer than the cached zip's own high-water
mark (and the zip's ETag moved). Sources.xz files are content-addressed, so a cached one is reused only when
its Release file still lists the same digest, and every download is checked against it.
"""
import base64
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

from feedlib import FeedError

USER_AGENT = "meshterm-vulnfeed-builder (+https://github.com/AG-Studio-Apps/meshterm-vulnfeed)"
OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
ZIP_CAP = 4 * 1024 ** 3          # Ubuntu's all.zip is about 0.8 GB
CSV_CAP = 64 * 1024 ** 2         # modified_id.csv is about 4 MB
RELEASE_CAP = 16 * 1024 ** 2
SOURCES_CAP = 256 * 1024 ** 2
_CHUNK = 1024 * 1024


def _request(url, method="GET"):
    return urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})


RETRY_DELAY = 5     # seconds before the first retry; then x3 (tests set 0)


def _retry(what, func, attempts=4):
    delay = RETRY_DELAY
    for attempt in range(1, attempts + 1):
        try:
            return func()
        except urllib.error.HTTPError as error:
            if error.code in (404, 410) or attempt == attempts:
                raise FeedError(f"{what}: HTTP {error.code}", transient=error.code >= 500) from None
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            if attempt == attempts:
                raise FeedError(f"{what}: {error}", transient=True) from None
        time.sleep(delay)
        delay *= 3


def get_bytes(url, cap):
    def once():
        with urllib.request.urlopen(_request(url), timeout=60) as response:
            data = response.read(cap + 1)
        if len(data) > cap:
            raise FeedError(f"{url} is larger than {cap} bytes")
        return data
    return _retry(url, once)


def download(url, dest, cap, expect_md5_b64=None, expect_digest=None, expect_size=None):
    """Streams url to dest (via dest.part), checking size and, when given, the md5 or an
    (algorithm, hex) digest such as ("sha256", "...")."""
    part = dest + ".part"

    def once():
        md5, size = hashlib.md5(), 0
        sha = hashlib.new(expect_digest[0]) if expect_digest else None
        headers = {}
        with urllib.request.urlopen(_request(url), timeout=120) as response, open(part, "wb") as handle:
            headers = dict(response.headers.items())
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    raise FeedError(f"{url} is larger than {cap} bytes")
                md5.update(chunk)
                if sha is not None:
                    sha.update(chunk)
                handle.write(chunk)
        if expect_size is not None and size != expect_size:
            raise OSError(f"{url}: {size} bytes, expected {expect_size} (truncated?)")
        if expect_md5_b64 and base64.b64encode(md5.digest()).decode() != expect_md5_b64:
            raise OSError(f"{url}: md5 does not match x-goog-hash")
        if expect_digest and sha.hexdigest() != expect_digest[1]:
            raise FeedError(f"{url}: {expect_digest[0]} does not match its Release file")
        return headers, size

    try:
        headers, size = _retry(url, once)
    except BaseException:
        if os.path.exists(part):
            os.remove(part)
        raise
    os.replace(part, dest)
    return headers, size


def head(url):
    def once():
        with urllib.request.urlopen(_request(url, "HEAD"), timeout=60) as response:
            return dict(response.headers.items())
    return _retry(url, once)


def goog_md5(headers):
    """The md5 (base64) from GCS's x-goog-hash header(s), or None."""
    for key, value in headers.items():
        if key.lower() == "x-goog-hash":
            for part in value.split(","):
                part = part.strip()
                if part.startswith("md5="):
                    return part[4:]
    return None


# --- OSV -----------------------------------------------------------------------------------------------
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$")


def ts_key(text):
    """A sortable key for an RFC 3339 UTC time with up to 9 fraction digits, or None."""
    match = _TS_RE.match(text or "")
    if not match:
        return None
    return match.group(1), (match.group(2) or "").ljust(9, "0")


def ts_seconds(text):
    """The time cut to whole seconds, `YYYY-MM-DDTHH:MM:SSZ`."""
    key = ts_key(text)
    if key is None:
        raise FeedError(f"bad OSV timestamp {text!r}")
    return key[0] + "Z"


def newest_in_csv(data):
    newest = None
    for line in data.decode("utf-8", "replace").splitlines():
        stamp = line.split(",", 1)[0].strip()
        key = ts_key(stamp)
        if key and (newest is None or key > newest[0]):
            newest = (key, stamp)
    if newest is None:
        raise FeedError("modified_id.csv has no timestamps")
    return newest[1]


def osv_dir(cache, ecosystem):
    return os.path.join(cache, "osv", ecosystem)


def load_state(cache, ecosystem):
    path = os.path.join(osv_dir(cache, ecosystem), "state.json")
    try:
        with open(path, "rb") as handle:
            state = json.loads(handle.read())
        return state if isinstance(state, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(cache, ecosystem, state):
    path = os.path.join(osv_dir(cache, ecosystem), "state.json")
    with open(path + ".tmp", "w") as handle:
        json.dump(state, handle, sort_keys=True)
    os.replace(path + ".tmp", path)


def fetch_osv_zip(cache, ecosystem, log, offline=False):
    """The cached all.zip path for ecosystem, refreshed when modified_id.csv shows a change."""
    directory = osv_dir(cache, ecosystem)
    os.makedirs(directory, exist_ok=True)
    zip_path = os.path.join(directory, "all.zip")
    state = load_state(cache, ecosystem)
    have = os.path.isfile(zip_path)
    if offline:
        if not have:
            raise FeedError(f"--offline: no cached {ecosystem} all.zip")
        log.info(f"osv {ecosystem}: offline, using the cached zip (high-water {state.get('highwater')})")
        return zip_path
    base = f"{OSV_BASE}/{urllib.request.quote(ecosystem)}"
    csv_newest = newest_in_csv(get_bytes(f"{base}/modified_id.csv", CSV_CAP))
    cached_hw = ts_key(state.get("highwater", ""))
    if have and cached_hw and ts_key(csv_newest) <= cached_hw:
        log.info(f"osv {ecosystem}: unchanged (modified_id.csv newest {csv_newest} <= cached zip "
                 f"{state['highwater']}); download skipped")
        return zip_path
    headers = head(f"{base}/all.zip")
    etag = headers.get("ETag") or headers.get("Etag") or headers.get("etag")
    if have and etag and etag == state.get("etag"):
        if cached_hw is None:
            log.info(f"osv {ecosystem}: cached zip has the live ETag; download skipped")
        else:
            log.warn(f"osv {ecosystem}: modified_id.csv shows {csv_newest}, newer than the cached zip, but the "
                     "zip's ETag has not moved yet (export lag); using the cached zip")
        return zip_path
    started = time.time()
    got, size = download(f"{base}/all.zip", zip_path, ZIP_CAP, expect_md5_b64=goog_md5(headers))
    state = {"etag": got.get("ETag") or etag, "bytes": size, "highwater": None, "csv_newest": csv_newest}
    save_state(cache, ecosystem, state)
    log.info(f"osv {ecosystem}: downloaded all.zip, {size} bytes in {time.time() - started:.0f} s")
    return zip_path


def record_highwater(cache, ecosystem, highwater):
    """Called after a full read of the zip: the newest `modified` it holds."""
    state = load_state(cache, ecosystem)
    state["highwater"] = highwater
    save_state(cache, ecosystem, state)


# --- archive Sources -----------------------------------------------------------------------------------
def by_hash_path(cache, algo, digest):
    return os.path.join(cache, "archive", "by-hash", f"{algo}-{digest}")


def fetch_by_hash(cache, url, algo, digest, size, used, offline=False):
    """A Sources.xz, from the content-addressed cache when present (re-hashed), else downloaded and checked."""
    path = by_hash_path(cache, algo, digest)
    used.add(os.path.basename(path))
    if os.path.isfile(path):
        hasher = hashlib.new(algo)
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                hasher.update(chunk)
        if hasher.hexdigest() == digest and os.path.getsize(path) == size:
            return path, False
        os.remove(path)
    if offline:
        raise FeedError(f"--offline: {url} ({digest[:12]}) is not cached")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    download(url, path, SOURCES_CAP, expect_digest=(algo, digest), expect_size=size)
    return path, True


def prune_by_hash(cache, used, log):
    directory = os.path.join(cache, "archive", "by-hash")
    if not os.path.isdir(directory):
        return
    removed = 0
    for name in os.listdir(directory):
        if name not in used:
            os.remove(os.path.join(directory, name))
            removed += 1
    if removed:
        log.info(f"archive cache: pruned {removed} Sources file(s) no Release lists any more")
