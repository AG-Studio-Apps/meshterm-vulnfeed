"""End-of-life dates for the signed manifest (S6): each `releases.<key>` entry carries `eol`, the LAST day the release
gets security fixes, and a base Ubuntu entry whose release has Ubuntu Pro also `eolPro`, the last day of ESM. Python 3
stdlib only.

A REVIEWED TABLE, not a build-time fetch: distro-info-data's CSVs on salsa are unsigned (only the .deb inside Debian's
archive is chain-verified), the dates change about twice a year, and a new network input in the builder is a new
failure mode. The builder sets the fields from this table on every build, carried-forward entries included (never
from an old build record), and check_manifest requires every entry to carry exactly the table's fields.

To update: read the vendor source named in the entry, change the date (or add the key), set `read` to the day you read
it, run the tests (tests/test_eol.py checks every release key, the format and eolPro >= eol), and say in the commit
which source changed. A release with no known date gets no entry (and its manifest entry no field).

Semantics, per source: distro-info-data's `eol` / `eol-esm` / `eol-lts` columns are the last supported day; Red Hat's
and AlmaLinux's "until 31 May" is the last day; Alpine's releases.json `eol_date` is taken as the last day.
"""
import datetime
import re

READ = "2026-11-05"

UBUNTU = "distro-info-data ubuntu.csv (eol, eol-esm columns)"
DEBIAN = "distro-info-data debian.csv (eol-lts column: Debian LTS; ELTS is a paid third party, not used)"
ALPINE = "alpinelinux.org/releases.json (eol_date)"
EL = ("Red Hat Enterprise Linux life cycle (end of Maintenance Support); AlmaLinux wiki release notes (security "
      "support until 31 May; for 8 the older 2029-03-01 figure is superseded). Rocky hosts use the rhel-* files")

# key -> {"eol": last supported day, "eolPro": last ESM day (base Ubuntu keys only), "source", "read"}.
TABLE = {
    "ubuntu-20.04": {"eol": "2025-05-29", "eolPro": "2030-04-23", "source": UBUNTU, "read": READ},
    "ubuntu-22.04": {"eol": "2027-06-01", "eolPro": "2032-04-21", "source": UBUNTU, "read": READ},
    "ubuntu-24.04": {"eol": "2029-05-31", "eolPro": "2034-04-25", "source": UBUNTU, "read": READ},
    "ubuntu-26.04": {"eol": "2031-05-29", "eolPro": "2036-04-23", "source": UBUNTU, "read": READ},
    "ubuntu-26.10": {"eol": "2027-07-15", "source": UBUNTU, "read": READ},     # an interim: no Ubuntu Pro
    "debian-11": {"eol": "2026-08-31", "source": DEBIAN, "read": READ},
    "debian-12": {"eol": "2028-06-30", "source": DEBIAN, "read": READ},
    "debian-13": {"eol": "2030-06-30", "source": DEBIAN, "read": READ},
    "alpine-3.20": {"eol": "2026-04-01", "source": ALPINE, "read": READ},
    "alpine-3.21": {"eol": "2026-11-01", "source": ALPINE, "read": READ},
    "alpine-3.22": {"eol": "2027-05-01", "source": ALPINE, "read": READ},
    "alpine-3.23": {"eol": "2027-11-01", "source": ALPINE, "read": READ},
    "alpine-3.24": {"eol": "2028-06-01", "source": ALPINE, "read": READ},
    "rhel-8": {"eol": "2029-05-31", "source": EL, "read": READ},
    "rhel-9": {"eol": "2032-05-31", "source": EL, "read": READ},
    "rhel-10": {"eol": "2035-05-31", "source": EL, "read": READ},
    "alma-8": {"eol": "2029-05-31", "source": EL, "read": READ},
    "alma-9": {"eol": "2032-05-31", "source": EL, "read": READ},
    "alma-10": {"eol": "2035-05-31", "source": EL, "read": READ},
}

FIELDS = ("eol", "eolPro")
_DAY = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
# The keys that may carry eolPro: a base Ubuntu release (never its -esm file, which carries neither field).
_PRO_KEY = re.compile(r"^ubuntu-[0-9]{2}\.[0-9]{2}\Z")


def is_day(text):
    """A YYYY-MM-DD string that is a real calendar date."""
    if not isinstance(text, str) or not _DAY.match(text):
        return False
    try:
        datetime.date.fromisoformat(text)
    except ValueError:
        return False
    return True


def may_carry_pro(key):
    return bool(_PRO_KEY.match(key))


def fields(key):
    """{"eol": ..., "eolPro": ...} (only the fields the table has) for a release key; {} for one with no entry."""
    entry = TABLE.get(key) or {}
    return {name: entry[name] for name in FIELDS if name in entry}


def check_fields(key, entry):
    """None when the eol / eolPro fields of a manifest entry are well formed, else the reason: real dates, eolPro only
    on a base Ubuntu key and never without eol, eolPro >= eol."""
    eol, pro = entry.get("eol"), entry.get("eolPro")
    if "eol" in entry and not is_day(eol):
        return f"eol {eol!r} is not a YYYY-MM-DD date"
    if "eolPro" in entry:
        if not may_carry_pro(key):
            return "eolPro is only for a base Ubuntu release (ubuntu-NN.NN)"
        if not is_day(pro):
            return f"eolPro {pro!r} is not a YYYY-MM-DD date"
        if "eol" not in entry:
            return "eolPro without eol"
        if pro < eol:
            return f"eolPro {pro} is before eol {eol}"
    return None


def apply(releases):
    """Sets every entry's eol / eolPro from the table (dropping any other value, e.g. one a carried-forward entry
    brought from an old build record). In place; returns `releases`."""
    for key, entry in releases.items():
        for name in FIELDS:
            entry.pop(name, None)
        entry.update(fields(key))
    return releases
