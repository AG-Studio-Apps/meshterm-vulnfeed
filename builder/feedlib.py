"""Shared helpers for the vulnfeed builder, signer and alert. Python 3 stdlib only."""
import hashlib
import json
import re

# The trusted comment is the app's contract (meshDeckShared SignedArtifactContract(label: "vulnfeed",
# kind: "host-vulns")): `version=` must be the SECOND token. The builder always signs with ` commit=`; an
# emergency signature may leave it out.
COMMENT_RE = re.compile(
    r"^vulnfeed=host-vulns version=([1-9][0-9]*) date=([0-9]{4}-[0-9]{2}-[0-9]{2})( commit=[0-9a-f]{40})?$")
GENERATED_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
# Plain N.N.N, no leading zeros (except a lone 0), no suffixes.
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")

MANIFEST_SCHEMA = 1
MANIFEST_CAP = 16 * 1024          # the manifest is about 3 KB with every S2 release in it
FILE_CAP = 600 * 1024             # plan 4.2: per-file raw size under 600 KB
CURATED_CAP = 64 * 1024
KEEP_BUILDS = 3                   # content-addressed files stay live for the last 3 builds

# Paths a manifest may reference, relative to v1/. `r/` is S2 (OSV release files).
FILE_RE = re.compile(r"^(curated-[0-9a-f]{16}\.json|r/[a-z0-9][a-z0-9.-]{0,40}-[0-9a-f]{16}\.json)$")


class FeedError(Exception):
    pass


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def content_name(prefix, data):
    """The content-addressed file name: <prefix>-<first 16 hex of sha256>.json."""
    return f"{prefix}-{sha256_hex(data)[:16]}.json"


def _no_duplicates(items):
    keys = [key for key, _ in items]
    if len(set(keys)) != len(keys):
        dup = sorted({k for k in keys if keys.count(k) > 1})
        raise FeedError(f"duplicate JSON key(s): {', '.join(dup)}")
    return dict(items)


def loads_strict(data):
    """json.loads that refuses duplicate keys, NaN/Infinity and non-UTF-8."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            raise FeedError("not UTF-8") from None
    def bad_constant(name):
        raise FeedError(f"JSON constant {name} is not allowed")
    try:
        return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=bad_constant)
    except json.JSONDecodeError as error:
        raise FeedError(f"not valid JSON: {error}") from None


def dumps(obj):
    """The one serialisation the builder writes: stable key order, ASCII, trailing newline."""
    return (json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def parse_version(text):
    match = VERSION_RE.fullmatch(text) if isinstance(text, str) else None
    if not match:
        raise FeedError(f"version {text!r} is not plain N.N.N")
    return tuple(int(part) for part in match.groups())


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def key_id_of_pub(text):
    """The minisign key id (16 upper-case hex) of a .pub file's text."""
    import base64
    lines = text.splitlines()
    if len(lines) < 2:
        raise FeedError("not a minisign public key")
    blob = base64.b64decode(lines[1].strip(), validate=True)
    if len(blob) != 42 or blob[:2] != b"Ed":
        raise FeedError("not an Ed25519 minisign public key")
    return blob[2:10][::-1].hex().upper()


def key_id_of_sig(data):
    """(key id, trusted comment) of a .minisig file's bytes."""
    import base64
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise FeedError("the signature is not text") from None
    if len(lines) < 4 or not lines[0].startswith("untrusted comment:") \
            or not lines[2].startswith("trusted comment: "):
        raise FeedError("the signature is not in minisign's format")
    try:
        blob = base64.b64decode(lines[1].strip(), validate=True)
    except ValueError:
        raise FeedError("the signature line is not base64") from None
    if len(blob) != 74 or blob[:2] not in (b"Ed", b"ED"):
        raise FeedError("the signature is not an Ed25519 minisign signature")
    return blob[2:10][::-1].hex().upper(), lines[2][len("trusted comment: "):]
