"""RPM (EL) version comparison: a from-scratch twin of rpm's rpmvercmp (rpm-6.1.0-release rpmio/rpmvercmp.cc) and
of the EVR order dnf and rpm use on top of it. Python 3 stdlib only.

rpmvercmp(a, b), segment by segment:
- Separators are every character that is not an ASCII letter or digit, `~` or `^`; runs of them are skipped (so
  `2.0` equals `2_0`, and `a+` equals `a_`).
- `~` sorts before everything, even the end of the string (`1.0~rc1 < 1.0`).
- `^` sorts after the end of the string but before any other segment (`1.0 < 1.0^git1 < 1.01`).
- A digit run compares numerically (leading zeros dropped, the longer run wins); a letter run compares as bytes;
  a digit run is newer than a letter run.
- When one side runs out, the side with characters left wins; equal segments with different separators are equal.

An EVR is `[epoch:]version[-release]`: the epoch (digits, missing = 0) compares as a number, then the version,
then the release, each with rpmvercmp. When either side has no release, releases are not compared (rpm's
rpmverCmp: `1.0` matches every `1.0-N`).

The shared vectors (tests/fixtures/rpm-vercmp.at, rpm's own tests/rpmvercmp.at) are the contract; meshTerm's
RpmVersion keeps an identical copy.
"""
import functools
import re

_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_DIGIT = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
# What the feed and the app accept as one EVR: an optional numeric epoch, a version and an optional release, each
# a run of letters, digits and . _ + ~ ^ (no `-` inside either part, no `:` after the epoch).
_EVR = re.compile(r"^(?:(\d{1,10}):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?\Z")


def rpmvercmp(a, b):
    """-1, 0 or 1, as rpm's rpmvercmp(a, b)."""
    if a == b:
        return 0
    one, two = 0, 0
    la, lb = len(a), len(b)

    def at(s, i):
        return s[i] if i < len(s) else ""

    while one < la or two < lb:
        while one < la and a[one] not in _ALNUM and a[one] not in "~^":
            one += 1
        while two < lb and b[two] not in _ALNUM and b[two] not in "~^":
            two += 1
        c1, c2 = at(a, one), at(b, two)
        if c1 == "~" or c2 == "~":
            if c1 != "~":
                return 1
            if c2 != "~":
                return -1
            one += 1
            two += 1
            continue
        if c1 == "^" or c2 == "^":
            if not c1:
                return -1
            if not c2:
                return 1
            if c1 != "^":
                return 1
            if c2 != "^":
                return -1
            one += 1
            two += 1
            continue
        if not (c1 and c2):
            break
        end1, end2 = one, two
        if c1 in _DIGIT:
            while end1 < la and a[end1] in _DIGIT:
                end1 += 1
            while end2 < lb and b[end2] in _DIGIT:
                end2 += 1
            isnum = True
        else:
            while end1 < la and a[end1] in _ALPHA:
                end1 += 1
            while end2 < lb and b[end2] in _ALPHA:
                end2 += 1
            isnum = False
        seg1, seg2 = a[one:end1], b[two:end2]
        if not seg1:
            return -1       # cannot happen (c1 is alphanumeric)
        if not seg2:
            return 1 if isnum else -1
        if isnum:
            seg1, seg2 = seg1.lstrip("0"), seg2.lstrip("0")
            if len(seg1) != len(seg2):
                return 1 if len(seg1) > len(seg2) else -1
        if seg1 != seg2:
            return 1 if seg1 > seg2 else -1
        one, two = end1, end2
    if one >= la and two >= lb:
        return 0
    return -1 if one >= la else 1


def parse(text):
    """(epoch int, version, release or None), or None when `text` is not an EVR the feed accepts."""
    if not isinstance(text, str):
        return None
    match = _EVR.match(text)
    if not match:
        return None
    epoch, version, release = match.groups()
    return int(epoch or 0), version, release


def validate(text):
    return parse(text) is not None


def compare(a, b):
    """-1, 0 or 1 for two EVRs (both must validate)."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        raise ValueError(f"not an rpm EVR: {a if pa is None else b!r}")
    if pa[0] != pb[0]:
        return -1 if pa[0] < pb[0] else 1
    rc = rpmvercmp(pa[1], pb[1])
    if rc or pa[2] is None or pb[2] is None:
        return rc
    return rpmvercmp(pa[2], pb[2])


sort_key = functools.cmp_to_key(compare)


_MODULAR = re.compile(r"\.module[_+]el|module\+el")


def is_modular(text):
    """A modular build's release (`8.1.14-1.module_el9.2.0+24+ca6bd7c2`, Red Hat's `...module+el9.2.0+...`)."""
    return bool(_MODULAR.search(text or ""))


def upstream_major_minor(text):
    """The first two numeric components of the version (`8.1.14` -> (8, 1)), or None."""
    parsed = parse(text)
    if parsed is None:
        return None
    numbers = re.findall(r"\d+", parsed[1])
    return tuple(int(n) for n in numbers[:2]) if len(numbers) >= 2 else None
