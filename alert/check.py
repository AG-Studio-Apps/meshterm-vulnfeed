#!/usr/bin/env python3
"""vulnfeed freshness alert: fetches the LIVE manifest and its signature, verifies them against the
committed public keys, and files ONE private issue in AG-Studio-Apps/meshTerm (label `vulnfeed`) when the
feed is stale (generated more than 24 h ago) or does not verify. The issue is closed when it recovers.

    check.py run          # what run.sh calls (the systemd timer)
    check.py evaluate     # prints the verdict as JSON; never touches gh

Environment (all optional):
    VULNFEED_ALERT_DRY_RUN       default 1: print what would be filed. Only 0 / false / no files for real.
    VULNFEED_ALERT_URL           site root, default https://ag-studio-apps.github.io/meshterm-vulnfeed
                                 (file:// works, for tests)
    VULNFEED_ALERT_KEYS_DIR      default keys/ beside this file (the installed copy), else the repo's keys/
    VULNFEED_ALERT_MAX_AGE_HOURS default 24
    VULNFEED_ALERT_GH_REPO       default AG-Studio-Apps/meshTerm (a PRIVATE repo, so the issue is private)
    VULNFEED_ALERT_STATE         default $XDG_STATE_HOME/vulnfeed-freshness
    VULNFEED_ALERT_RECORD_URL    where builds/<serial>.json is read, default the COMMITTED record on main
                                 (raw.githubusercontent.com); unset with a non-default VULNFEED_ALERT_URL, the
                                 record check is skipped (tests, local sites)
    VULNFEED_ALERT_STALE_RELEASE_HOURS  default 48

The S2 release files are fail-soft: a release that fails a build keeps its previous file, and the build record
(unsigned, committed by the workflow's record job) marks it `stale` with the time it first failed. A release
carried forward for more than 48 h is its own problem kind, `stale-release`, so the issue says which release
stopped refreshing even while the feed as a whole is fresh.
"""
import datetime
import hashlib
import http.client
import json
import os
import secrets
import subprocess
import time
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
for extra in (HERE, os.path.join(HERE, "..", "builder"), os.path.join(HERE, "..", "scripts")):
    if extra not in sys.path:
        sys.path.insert(0, extra)
from feedlib import FILE_CAP, MANIFEST_CAP, FeedError, loads_strict  # noqa: E402
import sign  # noqa: E402

DEFAULT_URL = "https://ag-studio-apps.github.io/meshterm-vulnfeed"
DEFAULT_RECORD_URL = "https://raw.githubusercontent.com/AG-Studio-Apps/meshterm-vulnfeed/main/builds"
RECORD_CAP = 256 * 1024
LABEL = "vulnfeed"
TITLE = "vulnfeed: the live host vulnerability feed is stale or does not verify"
SIG_CAP = 4 * 1024
RECOMMENT_HOURS = 24


def _default_keys_dir():
    installed = os.path.join(HERE, "keys")
    return installed if os.path.isdir(installed) else os.path.join(HERE, "..", "keys")


def _parse_time(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def _iso(moment):
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


RETRY_DELAY = float(os.environ.get("VULNFEED_ALERT_RETRY_DELAY", "30"))


def _fetch_once(url, cap):
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache",
                                                   "User-Agent": "meshterm-vulnfeed-freshness"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(cap + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise FeedError(f"HTTP {error.code} for {url}", transient=error.code >= 500) from None
    except http.client.HTTPException as error:
        # IncompleteRead and friends are not OSError; without this the run crashes and nothing is filed.
        raise FeedError(f"{type(error).__name__} reading {url}", transient=True) from None
    except (OSError, urllib.error.URLError) as error:
        raise FeedError(f"{url}: {error}", transient=True) from None
    if len(data) > cap:
        raise FeedError(f"{url} is larger than {cap} bytes")
    return data


def fetch(url, cap, token=None):
    """One retry after RETRY_DELAY seconds for network errors and 5xx, so a single blip files no issue."""
    if token and url.startswith(("http://", "https://")):
        url = f"{url}?r={token}"
    try:
        return _fetch_once(url, cap)
    except FeedError as error:
        if not getattr(error, "transient", False):
            raise
    time.sleep(RETRY_DELAY)
    return _fetch_once(url, cap)


def evaluate(base_url, keys_dir, now, max_age_hours=24, record_url=None, stale_release_hours=48):
    """The verdict: {"ok", "problems": [{"kind", "detail"}], "serial", "generated", "age_hours", "signer"}."""
    base = base_url.rstrip("/")
    token = secrets.token_hex(8)
    result = {"ok": False, "problems": [], "serial": None, "generated": None, "age_hours": None, "signer": None,
              "checked": _iso(now), "url": f"{base}/v1/manifest.json"}

    def problem(kind, detail):
        result["problems"].append({"kind": kind, "detail": str(detail)[:300]})
        return result

    try:
        body = fetch(f"{base}/v1/manifest.json", MANIFEST_CAP, token)
    except (OSError, urllib.error.URLError, FeedError) as error:
        return problem("fetch-manifest", error)
    try:
        signature = fetch(f"{base}/v1/manifest.json.minisig", SIG_CAP, token)
    except (OSError, urllib.error.URLError, FeedError) as error:
        return problem("fetch-signature", error)
    try:
        signer, serial, comment = sign.check_pair(body, signature, "any", keys_dir)
    except FeedError as error:
        return problem("verify", error)
    result.update(signer=signer, serial=serial, comment=comment)
    if signer == "emergency":
        # Not a failure: the recovery path is working. Still worth an issue, so nobody forgets to rotate.
        problem("emergency-key", "the live manifest is signed with the EMERGENCY key")
    manifest = loads_strict(body)
    try:
        generated = _parse_time(manifest["generated"])
    except (KeyError, TypeError, ValueError):
        return problem("verify", f"generated {manifest.get('generated')!r} is not UTC ISO 8601")
    result["generated"] = manifest["generated"]
    age = (now - generated).total_seconds() / 3600
    result["age_hours"] = round(age, 1)
    if age > max_age_hours:
        problem("stale", f"generated {manifest['generated']}, {age:.1f} h ago (limit {max_age_hours} h)")
    elif age < -1:
        problem("future", f"generated {manifest['generated']} is in the future")
    curated = manifest.get("curated") or {}
    try:
        data = fetch(f"{base}/v1/{curated.get('file')}", FILE_CAP, token)
        if hashlib.sha256(data).hexdigest() != curated.get("sha256"):
            problem("curated-sha256", f"{curated.get('file')} does not match the signed sha256")
    except (OSError, urllib.error.URLError, FeedError) as error:
        problem("fetch-curated", f"{curated.get('file')}: {error}")
    if record_url:
        check_record(record_url, manifest, now, stale_release_hours, problem, result)
    result["ok"] = not result["problems"]
    return result


def check_record(record_url, manifest, now, limit_hours, problem, result):
    """The committed build record of the live serial: any release carried forward (`stale`) for more than
    `limit_hours` is a `stale-release` problem. The record job commits right after signing, so a record that
    is missing 90 minutes after the build (the timer's offset) is itself a problem (`fetch-record`)."""
    serial = manifest.get("serial")
    try:
        record = loads_strict(fetch(f"{record_url.rstrip('/')}/{serial}.json", RECORD_CAP, secrets.token_hex(8)))
    except (OSError, urllib.error.URLError, FeedError) as error:
        return problem("fetch-record", f"builds/{serial}.json: {error}")
    if not isinstance(record, dict) or record.get("serial") != serial:
        return problem("fetch-record", f"builds/{serial}.json does not record serial {serial}")
    old = []
    for key, info in sorted((record.get("stale") or {}).items()):
        try:
            since = _parse_time(info["since"])
        except (KeyError, TypeError, ValueError):
            old.append(f"{key} (no valid since)")
            continue
        hours = (now - since).total_seconds() / 3600
        if hours > limit_hours:
            old.append(f"{key} since {info['since']} ({hours:.0f} h: {str(info.get('reason', ''))[:80]})")
    result["stale_releases"] = sorted((record.get("stale") or {}))
    if old:
        problem("stale-release", f"carried forward for more than {limit_hours:.0f} h: " + "; ".join(old))


def fingerprint(result):
    """What makes a new comment worth posting: the set of problem kinds (not the ages, which move)."""
    return ",".join(sorted({p["kind"] for p in result["problems"]}))


def body_text(result):
    lines = [f"Checked {result['checked']} from this box (`vulnfeed-freshness.timer`).", "",
             f"- URL: {result['url']}",
             f"- Live serial: {result['serial'] if result['serial'] is not None else 'unknown'}",
             f"- Generated: {result['generated'] or 'unknown'}"
             + (f" ({result['age_hours']} h ago)" if result["age_hours"] is not None else ""),
             f"- Signed by: {result['signer'] or 'unverified'}", "", "Problems:"]
    lines += [f"- **{p['kind']}**: {p['detail']}" for p in result["problems"]] or ["- none"]
    lines += ["", "Devices keep the last verified feed and hide its findings once it is 7 days old. Check the "
              "`Build vulnfeed` workflow runs in AG-Studio-Apps/meshterm-vulnfeed (a disabled schedule, a "
              "failed gate, or a missing VULNFEED_MINISIGN_KEY). This issue closes itself on recovery."]
    return "\n".join(lines)


class Gh:
    """gh, or a recorder when dry-running. `runner` is injectable for tests."""

    def __init__(self, repo, dry_run, runner=None, out=print):
        self.repo, self.dry_run, self.out = repo, dry_run, out
        self.runner = runner or (lambda args: subprocess.run(["gh", *args], capture_output=True, text=True,
                                                             timeout=120))

    def call(self, *args, mutating=True):
        if mutating and self.dry_run:
            self.out("(dry-run) gh " + " ".join(args[:3]) + " ...")
            return ""
        result = self.runner(list(args) + ["--repo", self.repo])
        if result.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args[:3])} failed: {(result.stderr or '').strip()[:300]}")
        return result.stdout

    def open_issue(self):
        try:
            out = self.call("issue", "list", "--state", "open", "--label", LABEL, "--limit", "50",
                            "--json", "number,title", mutating=False)
        except (RuntimeError, OSError) as error:
            if not self.dry_run:
                raise
            self.out(f"(dry-run) cannot list issues ({error}); assuming none is open")
            return None
        for issue in json.loads(out or "[]"):
            if issue.get("title") == TITLE:
                return issue["number"]
        return None


def act(result, gh, state, now, out=print):
    """File, refresh or close the issue. Returns the action taken. `state` is a dict, updated in place."""
    number = gh.open_issue()
    if result["ok"]:
        state.pop("fingerprint", None)
        state.pop("commented", None)
        if number is None:
            return "healthy"
        gh.call("issue", "comment", str(number), "--body",
                f"Recovered {result['checked']}: serial {result['serial']}, generated {result['generated']}, "
                f"verified against the {result['signer']} key. Closing.")
        gh.call("issue", "close", str(number))
        return f"closed #{number}"
    text = body_text(result)
    fp = fingerprint(result)
    if number is None:
        gh.call("issue", "create", "--label", LABEL, "--title", TITLE, "--body", text)
        state.update(fingerprint=fp, commented=_iso(now))
        if gh.dry_run:
            out(text)
        return "filed"
    last = state.get("commented")
    overdue = last is None or (now - _parse_time(last)).total_seconds() > RECOMMENT_HOURS * 3600
    if state.get("fingerprint") != fp or overdue:
        gh.call("issue", "comment", str(number), "--body", text)
        state.update(fingerprint=fp, commented=_iso(now))
        if gh.dry_run:
            out(text)
        return f"refreshed #{number}"
    return f"unchanged #{number}"


def _dry_run_from_env():
    return os.environ.get("VULNFEED_ALERT_DRY_RUN", "1").strip().lower() not in ("0", "false", "no")


def main(argv=None, runner=None, now=None):
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0] if argv else "run"
    now = now or datetime.datetime.now(datetime.timezone.utc)
    url = os.environ.get("VULNFEED_ALERT_URL", DEFAULT_URL)
    keys_dir = os.environ.get("VULNFEED_ALERT_KEYS_DIR") or _default_keys_dir()
    max_age = float(os.environ.get("VULNFEED_ALERT_MAX_AGE_HOURS", "24"))
    record_url = os.environ.get("VULNFEED_ALERT_RECORD_URL") or (DEFAULT_RECORD_URL if url == DEFAULT_URL else None)
    stale_hours = float(os.environ.get("VULNFEED_ALERT_STALE_RELEASE_HOURS", "48"))
    result = evaluate(url, keys_dir, now, max_age, record_url, stale_hours)
    if command == "evaluate":
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0 if result["ok"] else 2
    if command != "run":
        print(__doc__, file=sys.stderr)
        return 2

    state_dir = os.environ.get("VULNFEED_ALERT_STATE") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "vulnfeed-freshness")
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, "state.json")
    try:
        with open(state_path) as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        state = {}
    dry = _dry_run_from_env()
    verdict = "ok" if result["ok"] else "PROBLEM " + "; ".join(f"{p['kind']}: {p['detail']}"
                                                               for p in result["problems"])
    print(f"{result['checked']} serial={result['serial']} generated={result['generated']} dry_run={int(dry)} {verdict}")
    gh = Gh(os.environ.get("VULNFEED_ALERT_GH_REPO", "AG-Studio-Apps/meshTerm"), dry, runner)
    try:
        action = act(result, gh, state, now)
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"gh failed, state NOT advanced: {error}", file=sys.stderr)
        return 1
    print(f"action: {action}")
    if not dry:
        tmp = state_path + ".tmp"
        with open(tmp, "w") as handle:
            json.dump(state, handle)
        os.replace(tmp, state_path)
    with open(os.path.join(state_dir, "last-result.json"), "w") as handle:
        json.dump(result, handle, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
