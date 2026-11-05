#!/usr/bin/env python3
"""Validates curated/curated.json. Authoritative (curated.schema.json is documentation).

The feed NEVER carries a shell command or a recipe: a compromised feed key can only add or hide a finding.
So every rule is a closed set of fields, each with a narrow shape, and anything else is refused, with a
pointed message when the field name looks like it would carry a command.

    validate_curated.py [FILE]          # default curated/curated.json
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feedlib import CURATED_CAP, FeedError, is_int, loads_strict, parse_version  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FILE = os.path.join(HERE, "..", "curated", "curated.json")

# Products whose probe and comparator are compiled into the app. A new one needs an app release first.
PRODUCTS = ("tailscale",)
KINDS = ("security", "recommended")
APPLIES_TO = ("any", "tailnet")
TOP_KEYS = {"rules"}
REQUIRED = {"id", "product", "below", "severity", "title", "fixedIn", "appliesTo"}
OPTIONAL = {"kind", "ids", "url"}
ALLOWED = REQUIRED | OPTIONAL
MAX_RULES = 200

# Names that would carry something to run. Refused by the closed field set anyway; named so the error says why.
COMMAND_WORDS = re.compile(r"(cmd|command|script|run|shell|exec|recipe|install|fix(?!edin)|action|args|argv|"
                           r"sudo|intent|hook|template|payload|eval|code)", re.IGNORECASE)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{2,63}$")
ADVISORY_RE = re.compile(r"^[A-Z][A-Z0-9]{0,15}(-[A-Z0-9]{1,16}){1,4}$")
URL_RE = re.compile(r"^https://[a-z0-9.-]+(/[A-Za-z0-9._~/%-]*)?$")
# Title: plain prose. No shell metacharacters, no control characters, no markup.
TITLE_RE = re.compile(r"^[A-Za-z0-9 .,:()'+/-]{3,120}$")


def _field_error(where, key):
    if COMMAND_WORDS.search(key):
        return f"{where}: field {key!r} is refused: the feed never carries a command, a recipe or anything to run"
    return f"{where}: unknown field {key!r}"


def validate(doc):
    """Returns a list of error strings (empty = valid)."""
    errors = []
    if not isinstance(doc, dict):
        return ["the file is not a JSON object"]
    for key in sorted(set(doc) - TOP_KEYS):
        errors.append(_field_error("top level", key))
    rules = doc.get("rules")
    if not isinstance(rules, list):
        return errors + ["`rules` must be an array"]
    if len(rules) > MAX_RULES:
        errors.append(f"{len(rules)} rules, at most {MAX_RULES}")
    seen = set()
    for index, rule in enumerate(rules):
        where = f"rules[{index}]"
        if not isinstance(rule, dict):
            errors.append(f"{where}: not an object")
            continue
        if isinstance(rule.get("id"), str):
            where = f"rule {rule['id']!r}"
        for key in sorted(set(rule) - ALLOWED):
            errors.append(_field_error(where, key))
        for key in sorted(REQUIRED - set(rule)):
            errors.append(f"{where}: missing {key!r}")

        rid = rule.get("id")
        if "id" in rule:
            if not isinstance(rid, str) or not ID_RE.match(rid):
                errors.append(f"{where}: id must match {ID_RE.pattern}")
            elif rid in seen:
                errors.append(f"{where}: duplicate id")
            else:
                seen.add(rid)
        if "product" in rule and rule["product"] not in PRODUCTS:
            errors.append(f"{where}: unknown product {rule['product']!r} (known: {', '.join(PRODUCTS)}); "
                          "a product needs a probe compiled into the app first")
        versions = {}
        for key in ("below", "fixedIn"):
            if key in rule:
                try:
                    versions[key] = parse_version(rule[key])
                except FeedError as error:
                    errors.append(f"{where}: {key}: {error}")
        if len(versions) == 2 and versions["fixedIn"] < versions["below"]:
            errors.append(f"{where}: fixedIn {rule['fixedIn']} is below the floor {rule['below']} "
                          "(installing it would not clear the finding)")
        if "severity" in rule and (not is_int(rule["severity"]) or not 1 <= rule["severity"] <= 4):
            errors.append(f"{where}: severity must be an integer 1-4")
        if "kind" in rule and rule["kind"] not in KINDS:
            errors.append(f"{where}: kind must be one of {', '.join(KINDS)}")
        if "appliesTo" in rule and rule["appliesTo"] not in APPLIES_TO:
            errors.append(f"{where}: appliesTo must be one of {', '.join(APPLIES_TO)}")
        if "title" in rule and (not isinstance(rule["title"], str) or not TITLE_RE.match(rule["title"])):
            errors.append(f"{where}: title must be 3-120 characters of plain prose ({TITLE_RE.pattern})")
        if "url" in rule and (not isinstance(rule["url"], str) or len(rule["url"]) > 200
                              or not URL_RE.match(rule["url"])):
            errors.append(f"{where}: url must be a plain https URL ({URL_RE.pattern})")
        if "ids" in rule:
            ids = rule["ids"]
            if not isinstance(ids, list) or len(ids) > 32 \
                    or not all(isinstance(i, str) and ADVISORY_RE.match(i) for i in ids):
                errors.append(f"{where}: ids must be up to 32 advisory ids like CVE-2026-1234 or TS-2026-014")
            elif len(set(ids)) != len(ids):
                errors.append(f"{where}: ids has duplicates")
    return errors


def load_and_validate(data):
    """Bytes in, parsed document out; raises FeedError with every problem."""
    if len(data) > CURATED_CAP:
        raise FeedError(f"curated file is {len(data)} bytes, at most {CURATED_CAP}")
    doc = loads_strict(data)
    errors = validate(doc)
    if errors:
        raise FeedError("curated rules are invalid:\n  " + "\n  ".join(errors))
    return doc


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else DEFAULT_FILE
    try:
        with open(path, "rb") as handle:
            doc = load_and_validate(handle.read())
    except (OSError, FeedError) as error:
        print(f"FAIL: {path}: {error}", file=sys.stderr)
        return 1
    print(f"OK: {path}: {len(doc['rules'])} rule(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
