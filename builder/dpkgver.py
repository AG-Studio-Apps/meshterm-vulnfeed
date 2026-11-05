"""Debian version parsing and comparison, faithful to Debian Policy 5.6.12 and dpkg's lib/dpkg/version.c
(parseversion + verrevcmp). Python 3 stdlib only.

    [epoch:]upstream_version[-debian_revision]

- epoch: an unsigned integer, default 0. Split at the FIRST colon.
- debian_revision: after the LAST hyphen, if any; absent means "" (which compares equal to "0").
- comparison: epoch numerically, then upstream, then revision, each with verrevcmp: alternate non-digit
  runs (compared character by character, `~` before everything, even the end of the string, then letters,
  then everything else by code point) and digit runs (compared numerically, leading zeros ignored).

`parse()` refuses what dpkg's parseversion refuses (empty, embedded blanks, bad or empty epoch, empty
upstream, upstream not starting with a digit, empty revision, characters outside the policy set), so the
builder can tell a real version from a nonsense one.
"""
import functools
import re

_UPSTREAM_CHARS = re.compile(r"^[A-Za-z0-9.+~:-]+$")
_REVISION_CHARS = re.compile(r"^[A-Za-z0-9.+~]+$")
_EPOCH_MAX = 2 ** 31 - 1  # dpkg refuses an epoch above INT_MAX


class VersionError(ValueError):
    pass


class DpkgVersion:
    __slots__ = ("epoch", "upstream", "revision", "text")

    def __init__(self, epoch, upstream, revision, text):
        self.epoch, self.upstream, self.revision, self.text = epoch, upstream, revision, text

    @classmethod
    def parse(cls, text):
        if not isinstance(text, str):
            raise VersionError("version is not a string")
        stripped = text.strip(" \t\n")
        if not stripped:
            raise VersionError("version string is empty")
        if any(c in stripped for c in " \t\n"):
            raise VersionError("version string has embedded spaces")
        epoch, colon, rest = stripped.partition(":")
        if colon:
            if not epoch:
                raise VersionError("epoch in version is empty")
            if not all(_digit(c) for c in epoch):
                raise VersionError("epoch in version is not number")
            value = int(epoch)
            if value > _EPOCH_MAX:
                raise VersionError("epoch in version is too big")
            if not rest:
                raise VersionError("nothing after colon in version number")
        else:
            value, rest = 0, stripped
        upstream, hyphen, revision = rest.rpartition("-")
        if not hyphen:
            upstream, revision = rest, ""
        elif not revision:
            raise VersionError("revision number is empty")
        if not upstream:
            raise VersionError("version number is empty")
        if not _digit(upstream[0]):
            raise VersionError("version number does not start with digit")
        if not _UPSTREAM_CHARS.fullmatch(upstream):
            raise VersionError("invalid character in version number")
        if revision and not _REVISION_CHARS.fullmatch(revision):
            raise VersionError("invalid character in revision number")
        return cls(value, upstream, revision, stripped)

    def __repr__(self):
        return f"DpkgVersion({self.text!r})"

    def _cmp(self, other):
        if self.epoch != other.epoch:
            return -1 if self.epoch < other.epoch else 1
        return verrevcmp(self.upstream, other.upstream) or verrevcmp(self.revision, other.revision)

    def __lt__(self, other):
        return self._cmp(other) < 0

    def __le__(self, other):
        return self._cmp(other) <= 0

    def __gt__(self, other):
        return self._cmp(other) > 0

    def __ge__(self, other):
        return self._cmp(other) >= 0

    def __eq__(self, other):
        return isinstance(other, DpkgVersion) and self._cmp(other) == 0

    def __hash__(self):
        raise TypeError("DpkgVersion is not hashable: equal versions can have different text (1.0 == 1.0-0)")


def _order(c):
    """dpkg's order(): `~` sorts lowest, then the end of the string (and digits), letters, the rest."""
    if c == "":
        return 0
    if "0" <= c <= "9":
        return 0
    if ("a" <= c <= "z") or ("A" <= c <= "Z"):
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _digit(c):
    return "0" <= c <= "9"


def verrevcmp(a, b):
    """dpkg's verrevcmp(), returning -1, 0 or 1."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _digit(a[i])) or (j < lb and not _digit(b[j])):
            ac = _order(a[i] if i < la else "")
            bc = _order(b[j] if j < lb else "")
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and _digit(a[i]) and _digit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _digit(a[i]):
            return 1
        if j < lb and _digit(b[j]):
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare(a, b):
    """Compares two version strings (each parsed strictly): -1, 0 or 1."""
    return DpkgVersion.parse(a)._cmp(DpkgVersion.parse(b))


def is_valid(text):
    try:
        DpkgVersion.parse(text)
    except VersionError:
        return False
    return True


sort_key = functools.cmp_to_key(compare)
