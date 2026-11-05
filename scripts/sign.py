#!/usr/bin/env python3
"""Signs and verifies v1/manifest.json exactly as meshTerm's contract does. Needs the `minisign` binary.

CI does NOT run this file to sign (the sign job runs no repository script; it repeats the same steps inline).
This is for local builds, the emergency key, and the tests.

    sign.py sign   --manifest out/v1/manifest.json --key FILE [--commit SHA] [--password-file FILE]
                   [--role feed|emergency] [--keys-dir keys]
    sign.py verify --manifest out/v1/manifest.json [--sig FILE] [--role feed|emergency|any]
                   [--keys-dir keys] [--require-commit]

A pair passes when: the signature names a key in keys/ (vulnfeed-feed.pub or vulnfeed-emergency.pub, by its
8-byte key id); minisign verifies the body and the trusted comment against that key; the trusted comment is
exactly `vulnfeed=host-vulns version=<serial> date=<YYYY-MM-DD>[ commit=<40 hex>]`; <serial> is the
manifest's `serial` (and `version`); <date> is the date of its `generated`. A recipes or catalogue signature
never passes (another kind token, and another key).
"""
import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "builder"))
from feedlib import COMMENT_RE, FeedError, is_int, key_id_of_pub, key_id_of_sig, loads_strict  # noqa: E402

KEYS_DIR = os.path.join(HERE, "..", "keys")
ROLES = ("feed", "emergency")


def roster(keys_dir=KEYS_DIR):
    """{role: (path, key id)} for keys/vulnfeed-<role>.pub."""
    out = {}
    for role in ROLES:
        path = os.path.join(keys_dir, f"vulnfeed-{role}.pub")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as handle:
                out[role] = (path, key_id_of_pub(handle.read()))
    if not out:
        raise FeedError(f"no vulnfeed-*.pub in {keys_dir}")
    ids = [kid for _, kid in out.values()]
    if len(set(ids)) != len(ids):
        raise FeedError("the feed and emergency keys share a key id")
    return out


def manifest_version(body):
    """(serial, date) a manifest's signature must carry."""
    doc = loads_strict(body)
    if not isinstance(doc, dict):
        raise FeedError("the manifest is not a JSON object")
    serial, version, generated = doc.get("serial"), doc.get("version"), doc.get("generated")
    if not is_int(serial) or serial < 1:
        raise FeedError("the manifest has no positive integer serial")
    if version != serial:
        raise FeedError(f"the manifest's version {version!r} is not its serial {serial}")
    if not isinstance(generated, str) or len(generated) < 10:
        raise FeedError("the manifest has no generated time")
    return serial, generated[:10]


def trusted_comment(serial, date, commit=None):
    comment = f"vulnfeed=host-vulns version={serial} date={date}"
    if commit:
        comment += f" commit={commit}"
    if not COMMENT_RE.match(comment):
        raise FeedError(f"would sign a malformed trusted comment {comment!r}")
    return comment


def check_pair(body, signature, role="any", keys_dir=KEYS_DIR, require_commit=False):
    """Raise FeedError unless the pair passes. Returns (role, serial, trusted comment)."""
    keys = roster(keys_dir)
    signer_id, comment = key_id_of_sig(signature)
    matches = [r for r, (_, kid) in keys.items() if kid == signer_id]
    if not matches:
        raise FeedError(f"the signature's key id {signer_id} is not in keys/ "
                        f"({', '.join(f'{r} {k}' for r, (_, k) in keys.items())})")
    signer = matches[0]
    if role != "any" and signer != role:
        raise FeedError(f"signed by the {signer} key, expected the {role} key")
    with tempfile.TemporaryDirectory() as tmp:
        body_path, sig_path = os.path.join(tmp, "manifest.json"), os.path.join(tmp, "manifest.json.minisig")
        with open(body_path, "wb") as handle:
            handle.write(body)
        with open(sig_path, "wb") as handle:
            handle.write(signature)
        result = subprocess.run(["minisign", "-V", "-q", "-p", keys[signer][0], "-m", body_path, "-x", sig_path],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise FeedError(f"minisign: the signature does not verify against vulnfeed-{signer}.pub "
                            f"({(result.stderr or result.stdout).strip()[:200]})")
    match = COMMENT_RE.match(comment)
    if not match:
        raise FeedError(f"trusted comment {comment!r} is not "
                        "'vulnfeed=host-vulns version=<serial> date=<YYYY-MM-DD>[ commit=<sha>]'")
    if require_commit and not match.group(3):
        raise FeedError("the trusted comment has no commit= (the feed key always signs one)")
    serial, date = manifest_version(body)
    if int(match.group(1)) != serial:
        raise FeedError(f"the signature is for serial {match.group(1)}, the manifest is serial {serial}")
    if match.group(2) != date:
        raise FeedError(f"the signature is dated {match.group(2)}, the manifest was generated {date}")
    return signer, serial, comment


def sign(manifest_path, key_path, commit=None, password_file=None, role="feed", keys_dir=KEYS_DIR):
    with open(manifest_path, "rb") as handle:
        body = handle.read()
    serial, date = manifest_version(body)
    comment = trusted_comment(serial, date, commit)
    sig_path = manifest_path + ".minisig"
    tmp_sig = sig_path + ".tmp"
    stdin = None
    if password_file:
        with open(password_file, "rb") as handle:
            stdin = handle.read()
    result = subprocess.run(["minisign", "-S", "-s", key_path, "-m", manifest_path, "-x", tmp_sig, "-t", comment],
                            input=stdin, capture_output=True)
    if result.returncode != 0:
        if os.path.exists(tmp_sig):
            os.unlink(tmp_sig)
        raise FeedError(f"minisign -S failed: {result.stderr.decode(errors='replace').strip()[:200]}")
    with open(tmp_sig, "rb") as handle:
        signature = handle.read()
    try:
        check_pair(body, signature, role, keys_dir, require_commit=bool(commit))
    except FeedError:
        os.unlink(tmp_sig)
        raise
    os.replace(tmp_sig, sig_path)
    return sig_path, comment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--manifest", required=True)
    s.add_argument("--key", required=True, help="the minisign SECRET key file")
    s.add_argument("--commit")
    s.add_argument("--password-file", help="for a passworded key (the emergency key); else minisign asks")
    s.add_argument("--role", choices=ROLES, default="feed")
    v = sub.add_parser("verify")
    v.add_argument("--manifest", required=True)
    v.add_argument("--sig")
    v.add_argument("--role", choices=("any",) + ROLES, default="any")
    v.add_argument("--require-commit", action="store_true")
    for p in (s, v):
        p.add_argument("--keys-dir", default=KEYS_DIR)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            path, comment = sign(args.manifest, args.key, args.commit, args.password_file, args.role, args.keys_dir)
            print(f"OK: wrote {path} ({comment})")
            return 0
        with open(args.manifest, "rb") as handle:
            body = handle.read()
        with open(args.sig or args.manifest + ".minisig", "rb") as handle:
            signature = handle.read()
        signer, serial, comment = check_pair(body, signature, args.role, args.keys_dir, args.require_commit)
    except (FeedError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"OK: serial {serial}, signed by the {signer} key ({comment})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
