"""Alpine (apk) version validation and comparison: a from-scratch twin of apk-tools v3.0.8 src/version.c
(token_first / token_next / token_cmp / apk_version_compare_fuzzy / apk_version_validate), with apk_blob_sort
and apk_blob_pull_uint from src/blob.c. Python 3 stdlib only.

    digit{.digit}...{letter}{_suffix{number}}...{~hash}{-rN}

Tokens, in the order they may appear: an initial digit run; `.digit` runs; one lowercase letter; `_suffix`
(alpha < beta < pre < rc < (none) < cvs < svn < git < hg < p) each with an optional number; `~` and a
lowercase-hex commit hash; `-r` and a revision number. Numbers are uint64 and wrap like apk_blob_pull_uint.
A `.digit` token with a leading zero on either side compares as a byte string (memcmp, then length:
apk_blob_sort), as does a commit hash. When one side runs out of equal tokens first: equal kinds are equal; a
pre-release suffix (< none) on the side that continues makes it LESS; otherwise the side whose next token kind
is HIGHER is LESS (so 1.0 < 1.0.1, 1.0 > 1.0_alpha, 1.0-r1 > 1.0, 1.0 > 1.0~abc ... by kind order).

The shared vectors (tests/fixtures/apk-version.data, apk-tools' own test/unit/version.data) are the contract;
meshTerm's ApkVersion keeps an identical copy.
"""
import functools

# enum PARTS
INITIAL_DIGIT, DIGIT, LETTER, SUFFIX, SUFFIX_NO, COMMIT_HASH, REVISION_NO, END, INVALID = range(9)

# DECLARE_SUFFIXES: INVALID = 0, ALPHA .. RC, NONE = 5, CVS .. P
SUFFIX_INVALID, SUFFIX_ALPHA, SUFFIX_BETA, SUFFIX_PRE, SUFFIX_RC, SUFFIX_NONE, SUFFIX_CVS, SUFFIX_SVN, \
    SUFFIX_GIT, SUFFIX_HG, SUFFIX_P = range(11)
_SUFFIXES = {b"alpha": SUFFIX_ALPHA, b"beta": SUFFIX_BETA, b"pre": SUFFIX_PRE, b"rc": SUFFIX_RC,
             b"cvs": SUFFIX_CVS, b"svn": SUFFIX_SVN, b"git": SUFFIX_GIT, b"hg": SUFFIX_HG, b"p": SUFFIX_P}

# apk_version.h result bits
EQUAL, LESS, GREATER, FUZZY, CONFLICT = 1, 2, 4, 8, 16
DEPMASK_ANY = EQUAL | LESS | GREATER

_MASK64 = (1 << 64) - 1
_DIGITS = frozenset(b"0123456789")
_LOWER = frozenset(b"abcdefghijklmnopqrstuvwxyz")          # APK_CTYPE_VERSION_SUFFIX
_HEX = frozenset(b"0123456789abcdef")                       # APK_CTYPE_HEXDIGIT


class _Tokens:
    """token_state over one version blob."""
    __slots__ = ("data", "pos", "token", "suffix", "number", "value")

    def __init__(self, data):
        self.data, self.pos = data, 0
        self.token, self.suffix, self.number, self.value = INITIAL_DIGIT, SUFFIX_INVALID, 0, b""
        self._digits()                                      # token_first

    def _digits(self):
        """token_parse_digits: apk_blob_pull_uint(b, 10), stopping at a NUL byte like the C loop."""
        data, start = self.data, self.pos
        number = 0
        while self.pos < len(data) and data[self.pos] != 0 and data[self.pos] in _DIGITS:
            number = (number * 10 + data[self.pos] - 48) & _MASK64
            self.pos += 1
        self.number = number
        self.value = data[start:self.pos]
        if not self.value:
            self.token = INVALID

    def _span(self, allowed):
        start = self.pos
        while self.pos < len(self.data) and self.data[self.pos] in allowed:
            self.pos += 1
        return self.data[start:self.pos]

    def next(self):
        """token_next."""
        data = self.data
        if self.pos >= len(data):
            self.token = END
            return
        c = data[self.pos]
        if c in _LOWER:
            if self.token > DIGIT:
                self.token = INVALID
                return
            self.value = data[self.pos:self.pos + 1]
            self.token = LETTER
            self.pos += 1
        elif c == 0x2E or c in _DIGITS:                      # '.' falls through to the digit case
            if c == 0x2E:
                if self.token > DIGIT:
                    self.token = INVALID
                    return
                self.pos += 1
            if self.token in (INITIAL_DIGIT, DIGIT):
                self.token = DIGIT
            elif self.token == SUFFIX:
                self.token = SUFFIX_NO
            else:
                self.token = INVALID
                return
            self._digits()
        elif c == 0x5F:                                      # '_'
            if self.token > SUFFIX_NO:
                self.token = INVALID
                return
            self.pos += 1
            self.value = self._span(_LOWER)
            self.suffix = _SUFFIXES.get(self.value, SUFFIX_INVALID)
            if self.suffix == SUFFIX_INVALID:
                self.token = INVALID
                return
            self.token = SUFFIX
        elif c == 0x7E:                                      # '~'
            if self.token >= COMMIT_HASH:
                self.token = INVALID
                return
            self.pos += 1
            self.value = self._span(_HEX)
            if not self.value:
                self.token = INVALID
                return
            self.token = COMMIT_HASH
        elif c == 0x2D:                                      # '-'
            if self.token >= REVISION_NO or data[self.pos:self.pos + 2] != b"-r":
                self.token = INVALID
                return
            self.pos += 2
            self.token = REVISION_NO
            self._digits()
        else:
            self.token = INVALID


def _blob_sort(a, b):
    """apk_blob_sort: memcmp over the shorter length, then the length. Python bytes order is exactly that."""
    return (a > b) - (a < b)


def _token_cmp(ta, tb):
    kind = ta.token
    if kind == DIGIT and (ta.value[:1] == b"0" or tb.value[:1] == b"0"):
        r = _blob_sort(ta.value, tb.value)
    elif kind in (DIGIT, INITIAL_DIGIT, SUFFIX_NO, REVISION_NO):
        r = (ta.number > tb.number) - (ta.number < tb.number)
    elif kind == LETTER:
        r = (ta.value > tb.value) - (ta.value < tb.value)
    elif kind == SUFFIX:
        r = (ta.suffix > tb.suffix) - (ta.suffix < tb.suffix)
    else:
        r = _blob_sort(ta.value, tb.value)
    return LESS if r < 0 else GREATER if r > 0 else EQUAL


def _blob(text):
    return text.encode("utf-8", "surrogateescape") if isinstance(text, str) else bytes(text)


def compare_fuzzy(a, b, fuzzy=False):
    """apk_version_compare_fuzzy: LESS, EQUAL or GREATER (the C result bits). None stands for a NULL blob."""
    if a is None or b is None:
        return EQUAL if a is None and b is None else EQUAL | GREATER | LESS
    ta, tb = _Tokens(_blob(a)), _Tokens(_blob(b))
    while ta.token == tb.token and ta.token < END:
        r = _token_cmp(ta, tb)
        if r != EQUAL:
            return r
        ta.next()
        tb.next()
    if ta.token == tb.token:
        return EQUAL
    if tb.token == END and fuzzy:
        return EQUAL
    if ta.token == SUFFIX and ta.suffix < SUFFIX_NONE:
        return LESS
    if tb.token == SUFFIX and tb.suffix < SUFFIX_NONE:
        return GREATER
    if ta.token > tb.token:
        return LESS
    if tb.token > ta.token:
        return GREATER
    return EQUAL


def compare(a, b):
    """-1, 0 or 1, by apk_version_compare (no validation: apk compares invalid versions too)."""
    r = compare_fuzzy(a, b, False)
    return -1 if r == LESS else 1 if r == GREATER else 0


def validate(text):
    """apk_version_validate."""
    t = _Tokens(_blob(text))
    while t.token < END:
        t.next()
    return t.token == END


def result_mask(op):
    """apk_version_result_mask_blob: the bits of an operator string such as `<=` or `~`; 0 for a bad one."""
    r = 0
    for c in op:
        if c == "<":
            r |= LESS
        elif c == ">":
            r |= GREATER
        elif c == "=":
            r |= EQUAL
        elif c == "~":
            r |= FUZZY | EQUAL
        else:
            return 0
    return r


def match(a, op, b):
    """apk_version_match(a, op bits, b)."""
    ok = (op & DEPMASK_ANY) == DEPMASK_ANY or bool(compare_fuzzy(a, b, bool(op & FUZZY)) & op)
    if op & CONFLICT:
        ok = not ok
    return ok


def is_valid(text):
    return isinstance(text, str) and validate(text)


sort_key = functools.cmp_to_key(compare)
