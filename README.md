# meshterm-vulnfeed

The signed host vulnerability feed meshTerm reads for "Security updates" (meshTerm
`docs/plan-host-cve-scanner.md`). Plain static JSON on GitHub Pages, rebuilt four times a day.

**Stages S2 + S4 (this state): curated rules plus OSV release files for dpkg and apk releases.** The manifest
carries the hand-written Tailscale rules and one release file per Ubuntu / Debian / Alpine release
(`builder/osvfeed.py`). The rpm family (S5) comes later.

## Layout

```
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/manifest.json          (+ .minisig, the only signed file)
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/curated-<sha256-16>.json
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/r/<release>-<sha256-16>.json
```

- `curated/curated.json`: the rules, reviewed in pull requests. `curated/curated.schema.json` documents them;
  `builder/validate_curated.py` is authoritative. A rule is a closed set of fields: `id`, `product` (only
  `tailscale`: a product needs a probe compiled into the app), `below` and `fixedIn` (plain `N.N.N`),
  `severity` (1-4), `kind` (`security`, the default, or `recommended`), `ids`, `title`, `url` (https),
  `appliesTo` (`any` or `tailnet`). **The feed never carries a command or a recipe**: any other field is
  refused, so a compromised feed key can only add or hide a finding.
- `builder/build.py`: writes `out/v1/manifest.json` and the content-addressed files, then gates them.
- `builder/osvfeed.py`: the OSV release files (rules and gates below); `builder/netfetch.py` its downloads and
  cache; `builder/dpkgver.py` Debian version comparison; `builder/apkver.py` Alpine version comparison (a twin
  of apk-tools v3.0.8 `src/version.c`, tested against apk-tools' own `test/unit/version.data`, kept
  byte-identical with meshTerm's copy in `tests/fixtures/apk-version.data`); `builder/cvss.py` CVSS 3.x and 4.0
  scores.
- `builder/baselines/debian-<n>.tsv`: release-day source versions, from snapshot.debian.org (`build.py baseline`).
- `builder/golden/`: the golden fixtures and their expectations (`expected.json`).
- `gates/`: the committed row-count minimums and reviewed overrides.
- `keys/archive/`: the Ubuntu and Debian archive keyrings the builder verifies InRelease files with.
- `builder/manifest.schema.json`: the manifest, as documentation (`check_manifest()` is authoritative).
- `scripts/sign.py`: local signing and verification (CI does not run it to sign).
- `keys/`: the two public keys the app pins. See `keys/README.md` for the ids and the Swift snippet.
- `builds/<serial>.json`: one per published build (the manifest, the files carried, the build log),
  committed by CI.
- `alert/`: the external freshness alert (a systemd user timer on the maintainer's machine).

## The manifest

```json
{"schema": 1, "serial": 12, "version": 12, "generated": "2026-11-05T05:10:00Z",
 "sources": {"osv": {"Debian": "2026-11-05T15:00:06Z", "Ubuntu": "2026-11-05T11:58:23Z"},
             "archive": {"noble": "2024-04-25T15:10:33Z", "noble-security": "2026-11-05T03:38:05Z", "...": "..."},
             "baseline": {"ubuntu-24.04": "2024-04-25", "debian-12": "2023-06-10", "...": "..."}},
 "releases": {"ubuntu-24.04": {"format": "dpkg", "file": "r/ubuntu-24.04-8dcc0c17b45f0405.json",
                               "sha256": "8dcc0c17...", "bytes": 38955, "rows": 892,
                               "eol": "2029-05-31", "eolPro": "2034-04-25"}, "...": {}},
 "curated": {"file": "curated-25abfc9f67145d28.json", "sha256": "25abfc9f...aa63b"}}
```

- `serial` is the number in the trusted comment; `version` repeats it so `SignedArtifactVerifier` reads it
  with no `bodyVersion:` argument.
- Serial = the highest `builds/<serial>.json` + 1, floored by the live manifest's serial (a deployed build whose
  `builds/` commit was lost must never have its serial reused: devices refuse the same serial with other bytes).
- Every file the manifest names is checked by its sha256. The files of the previous 2 builds are carried
  forward (fetched from the live site and checked against their `builds/` record), so 3 builds stay live.
- Gate before signing: the manifest's exact shape, canonical bytes, under 16 KB; release keys on the allowlist and
  the fixed `sources` shape; every named file present and matching its sha256; every release file's schema;
  every file under 600 KB; no unexpected file, no symlink; the curated file re-validates. The sign job repeats the
  format ties inline: an `alpine-*` entry must be `apk`, every other `dpkg`; each release body's `format` must
  equal its entry's; `sources.archive` may be empty only when every release is an Alpine one. For an rpm body it
  also checks the compact tables hold together (review L7): `ids` sorted unique CVEs, every fix 5 fields with sorted,
  unique, in-range id indexes, every binary's fix indexes the same, and no id or fix that nothing refers to.

## Release files (`v1/r/`)

```json
{"release":"ubuntu-24.04","format":"dpkg","keyedBy":"source",
 "pkgs":{"apt":[["0","2.8.4ubuntu0.1",3,["CVE-2026-109518"],"2026-11-03"]]},
 "kernel":{"linux-aws-6.8":[["0","6.8.0-1040.42~22.04.1",3,57,"2026-10-30"]]}}
```

A package row is `[introduced, fixed, severity, ids, publishedDate]` (severity 3 High, 4 Critical; ids are the
High/Critical CVEs fixed there); a kernel row is `[introduced, fixed, maxSeverity, count, publishedDate]`.
`publishedDate` (S7c on package rows) is the day the fix's advisory was published, `YYYY-MM-DD`; null when no
advisory dates it. It is the EARLIEST `published` of the advisories (USN/DSA/DLA) naming that fix (one row folds
every record naming the same (source, introduced, fixed), and the earliest is the day the fix first shipped; a
later advisory re-listing it is not a newer fix). A fix named only by `UBUNTU-CVE-*` / `DEBIAN-CVE-*` records ships
null: their `published` is the CVE's disclosure, often years before the fix (the intermediates and the golden
cases still use it as a fallback). Kernel rows keep their own date rule. The app reads a package row's first 4 elements, so the 5th is
optional: a file built before S7c has 4-element rows and still passes every check. Keyed by SOURCE
package: hosts match `${source:Package}` / `${source:Version}`.

Releases (`RELEASES` in `builder/osvfeed.py`, and the sign job's allowlist): `ubuntu-20.04`, `-22.04`, `-24.04`,
`-26.04`, `-26.10` (the current interim; 25.10 is end of life), `ubuntu-<lts>-esm` (the `Ubuntu:Pro:<lts>` rows,
for hosts with Ubuntu Pro attached), `debian-11`, `-12`, `-13`, `alpine-3.20` .. `alpine-3.24` (`Alpine:v3.20` ..
`Alpine:v3.24`), `alma-8` .. `alma-10` and `rhel-8` .. `rhel-10` (S5). **alpine-3.20 (EOL 2026-04-01) and alpine-3.21 (EOL 2026-11-01) are past end of life**
(alpinelinux.org/releases.json). James decided (2026-11-05) to keep them while secdb still publishes their
branches; the app's S6 adds an end-of-life note for such hosts.

### End of life (S6: `eol`, `eolPro`)

Each release entry carries `eol`, the LAST day the release gets security fixes (`YYYY-MM-DD`, a real calendar
date). A base Ubuntu entry (`ubuntu-NN.NN`) whose release has Ubuntu Pro also carries `eolPro`, the last day of ESM,
never before `eol`. The `-esm` entries carry neither (the app reads the base entry). A release with no known date
carries no field. The fields come from a REVIEWED TABLE, `builder/eol.py`, never from a build-time fetch
(distro-info-data's CSVs on salsa are unsigned, the dates change about twice a year, and a new network input is a new
failure mode). The builder sets them on every build, carried-forward entries included (an old record's value is
dropped), and `check_manifest` requires each entry to carry exactly the table's fields. The sign job checks them
inline: real dates, `eolPro` only on an `ubuntu-NN.NN` key and only with an `eol` it is not before.

Sources (read 2026-11-05; each entry records its source and read date): Ubuntu, distro-info-data `ubuntu.csv`
(`eol`, `eol-esm`); Debian, distro-info-data `debian.csv` `eol-lts` (Debian LTS; ELTS is a paid third party, not
used); Alpine, alpinelinux.org `releases.json` `eol_date` (taken as the last day); RHEL and AlmaLinux, the end of
Maintenance Support on Red Hat's life cycle page and AlmaLinux's release notes ("until 31 May" is the last day; 8's
older 2029-03-01 figure is superseded). Rocky hosts use the `rhel-*` dates.

**Updating the table**: read the vendor source, change the date (or add the key) in `builder/eol.py`, set that entry's
`read` to the day you read it, and run the tests: `tests/test_eol.py` fails for a release key (not `-esm`) with no
entry and no reason in its `NO_DATE`, a malformed date, or an `eolPro` on the wrong key or before `eol`. Adding a
release (below) needs its entry too.

### Alpine (S4, `format: "apk"`)

```json
{"release":"alpine-3.22","format":"apk","keyedBy":"origin",
 "pkgs":{"openssl":[["0","3.3.2-r0",3,["CVE-2024-0001"],null],["3.3.0","3.3.2-r1",4,["CVE-2024-0002"],null]]},
 "kernel":{"linux-lts":[["0","6.6.58-r0",4,12,null]]}}
```

Keyed by ORIGIN (`o:` in `/lib/apk/db/installed`; origin names may contain `_`). `introduced` is `"0"` or an apk
version: OSV Alpine gives the UPSTREAM version (`2.9.2`, below every `2.9.2-rN`), kept as is (18% of rows have one).
Differences from the dpkg rules:

- **Not-affected markers**: a range whose fixed is `"0"` or `"0-r0"` (secdb's "this branch never had it", e.g. db
  CVE-2016-0682) is dropped whole and counted (`not-affected range (fixed 0) dropped`).
- **`introduced` normalisation** (review H1, James 2026-11-05; narrowed by review L4): an imagemagick origin's
  upstream `X.Y.Z-N` is the version aports writes dotted, so `7.0.0-0` / `6.9.10-54` become `7.0.0.0` / `6.9.10.54`
  (`[7.0.0-0, 7.1.2.15-r0)` ships as `[7.0.0.0, 7.1.2.15-r0)`). Rejecting them, as the first S4 build did, silently
  dropped current Critical ImageMagick fixes on alpine-3.24. Any other origin's `X.Y.Z-0` (go's `1.21.0-0`, semver's
  "lowest 1.21.0") becomes plain `1.21.0`: the dotted `1.21.0.0` sorts above go's own `1.21.0-r0` and would miss
  it. Any other unparseable `introduced` (dates: libdwarf `1999-12-14`, jq `2026-04-02`; another origin's `X.Y.Z-N`
  with N > 0, none on 2026-11-05) is read as `"0"`, which widens the range to every version below the fix. All
  kinds are counted per release in the build log (`introduced: N normalised to the dotted form, N X.Y.Z-0 read as
  X.Y.Z, N range(s) restarted after a bad fix, M unparseable read as "0" (x% of its fixed range events)`); the
  `"0"` kind has its own zip-wide 2% gate (`INTRODUCED_REJECT_LIMIT`, as a share of the zip's fixed range events;
  the per-release share is in the log). On the 2026-11-05 zip: 480 imagemagick values dotted, 6 go values.
- **Range rule**: a fixed value apk cannot order (`opensmtpd 6.6.2p1-r0`) is taken out of the range first, so it
  can neither unsort the walk nor cost the range a good fix; it is rejected on its own, and an introduced that then
  follows an open one restarts the range there (review L5): `[0, 1.0p1-r0, 2.0, 2.1-r0]` ships `[2.0, 2.1-r0)` and
  rejects `[0, 1.0p1-r0)`, never the widened `[0, 2.1-r0)` (counted as `range(s) restarted after a bad fix`). The
  trade-off, chosen deliberately: a host BELOW the bad fix (here below `1.0p1-r0`) is not flagged for that CVE,
  since its range is the rejected one, in exchange for never flagging a host in the gap between the bad fix and the
  next introduced (`[1.0p1-r0, 2.0)`), which the widened range would flag although secdb says it is fixed. Widening
  turns one unorderable value into false positives on every host in the gap; restarting loses only the hosts old
  enough to predate a fix apk cannot even order. None on the 2026-11-05 zip (Alpine 3.20 to 3.24). The remaining events are
  sorted by apk version (`"0"` lowest) and walked as OSV does; each (introduced, the FIRST fixed after it) is one
  row. A later fixed of a closed range (`[0, f1, f2, f3]`) is `redundant fixed`, and a fixed below its introduced
  (prosody `[13.0.0, 0.12.6-r0)`) an `empty range`: both dropped and counted, not failures. Other event kinds or
  range types fail the release, as for dpkg.
- **First fixed only (OSV parity, review L3, kept deliberately).** `[0, f1, f2]` means affected below f1; the later
  fixed events are redundant (secdb lists every release that mentions the CVE in `secfixes`). Real examples:
  postgresql17 CVE-2026-2006 on alpine-3.21..3.24 is `[0, 17.8-r0, 17.9-r0]`, so a host on 17.8-r0 is not flagged
  (17.9-r0 re-lists the CVE); postgresql16 on 3.20..3.24 is `[0, 16.12-r0, 16.13-r0]`; intel-ucode is
  `[0, 20190514a-r0, 20190618-r0, 20191112-r0]`. A host between f1 and f2 is therefore not flagged, exactly as
  OSV's own matcher answers.
- **Rejects**: a date-shaped fixed value, or one apk-tools' validator refuses (`opensmtpd 6.6.2p1-r0`, `sudo
  1.9.5p2-r0`), is rejected and counts toward the 0.5% gate.
- **No baseline cut and no published check.** Alpine fixes come from secdb, which is built from each branch's
  aports `secfixes`, so a fix listed for a branch is in that branch's repository. There is no archive check yet:
  APKINDEX.tar.gz is RSA-signed with Alpine's keys, which the Python stdlib cannot verify. No release-day archive
  exists to cut against, and a fix older than the release never matches a host of it anyway.
- **Severity**: the highest CVSS 3.x/4.0 score, else Medium (not shipped).
- **Kernel**: `linux-lts`, `linux-edge`, `linux-rpi`, `linux-virt`, `linux-stable` fold to kernel rows (not
  `linux-pam`, `linux-headers`, `linux-firmware*`, `linux-tools`), with a **null** publishedDate: OSV Alpine
  has no fix date (a record's `published` is the CVE's NVD date, older than the fix), and the app never counts
  a pending kernel restart from a null date. Package rows carry the same null 5th element (S7c, the kernel
  rows' convention).
- **Golden cases** (`builder/golden/*.apk.txt`): the app's Pro probe output (`grep -E "^([PVo]:|$)"
  /lib/apk/db/installed`, as uid 1000) from stock `alpine:3.20`, `alpine:3.20.0` and `alpine:latest`. They are
  matched against the shipped rows exactly as the app does (per origin the highest installed version;
  `introduced <= installed < fixed`). With no fix dates and no archive snapshot, a frozen image gains hits as
  fixes land, so `alpine:3.20.0` and `alpine:latest` are `atLeast` cases; `alpine:3.20` (3.20.10, end of life)
  flags nothing and is `exact: []`, the Alpine false-positive gate. Every apk case, `atLeast` too, fails on 3 or
  more unexpected origins (`EXTRA_HIT_LIMIT`); 1 or 2 warn.

### AlmaLinux and RHEL (S5, `format: "rpm"`)

```json
{"release":"alma-9","format":"rpm","keyedBy":"binary",
 "ids":["CVE-2026-0001","CVE-2026-0002","CVE-2026-0003"],
 "fixes":[["0","1:3.5.8-2.el9_8",3,[0,1],[],"2026-10-14"],["0","8.2.33-1.module_el9.8.0+303+1bef6c12",4,[2],["php:8.2"],"2026-10-02"]],
 "pkgs":{"openssl":[0],"openssl-libs":[0],"php-cli":[1]},
 "kernel":{"kernel-core":[["0","5.14.0-611.5.1.el9_8",4,12,"2026-10-01"]]}}
```

Releases `alma-8`, `alma-9`, `alma-10` (OSV `AlmaLinux:<major>`) and `rhel-8`, `rhel-9`, `rhel-10` (OSV `Red Hat`:
one file per major merging `enterprise_linux:<major>::baseos`, `::appstream` and `::crb`; RHEL 10 publishes per minor
release, `enterprise_linux:10.0`, `10.1` ..., all merged). EUS / AUS / E4S / TUS streams and the add-on
repositories (realtime, nfv, sap, highavailability ...) are left out: a host on them is matched against the main
repositories only. **Rocky Linux hosts use the RHEL file**: Rocky's own OSV data is incomplete (`Rocky Linux:9` has
no openssl-libs), and Rocky rebuilds RHEL's sources at the same NEVRA (a Rocky-only `.rocky.0.1` rebuild sorts below
RHEL's next `.el9_N` fix, which is right). Differences from the dpkg rules:

- **Fixes that may lag (review L3).** Two cases flag a package the host cannot update yet. A **Rocky host** is
  matched against Red Hat's fixes, and Rocky ships each one days to weeks later: on 2026-11-05 RESF's 9.8 image was
  flagged for libcap `2.48-10.el9_8.1` (Red Hat, Important) while Rocky's baseos still had only `2.48-10.el9_7.1`.
  An **EUS / AUS host** (pinned to a minor release) is matched against the main repositories, whose fixes are built for
  the newest minor (`.el9_8`); its own EUS build (`.el9_6.4`) can sort below that and stay flagged. Neither is a
  wrong finding (the CVE is fixed upstream and the host lacks it), but Install Updates may install nothing. The app's
  Security updates sheet says so for every rpm host ("Some fixes may not be available from your vendor yet."); the
  finding clears at the first check after the vendor ships it.

- **Keyed by BINARY rpm name**: OSV's EL records name binaries (`openssl`, `openssl-libs`, `openssl-devel`) and no
  source rpm, so the file is COMPACT: a sorted CVE table, a fix table sorted by fixed EVR (`[introduced, fixed,
  severity, [id index ...], [module stream ...], publishedDate]`; the date, S7c, is the earliest `published` of the
  advisories naming that fix for any of its binaries (taken before any fit-to-cap pruning), or null, and the app
  reads only the first 5 elements) and per
  binary the indexes of its fixes. The row count is the
  (binary, fix) pairs plus the kernel rows. The app groups its findings by each binary's SOURCERPM.
- **Versions** are EVRs compared by `builder/rpmver.py` (rpm-6.1.0 rpmvercmp, its own vectors shared with the app).
- **Only records naming an upstream CVE ship** (ALBA / ALEA / most RHBA name none); `-debuginfo` / `-debugsource`
  binaries are dropped; of the kernel's binaries only `kernel-core` and its variants (`kernel-rt-core`,
  `kernel-64k-core`, `kernel-debug-core` ...) ship, as kernel rows dated by their advisory (the app matches
  `kernel-core-$(uname -r)` only); `kernel`, `kernel-modules*`, `kernel-tools*`, `kernel-headers` are dropped and
  counted, and so are the userspace binaries the kernel source builds (`perf`, `python3-perf`, `bpftool`, `rtla`,
  `rv`, `libperf`, review L2: their fix is the kernel advisory, so they would list the kernel's CVEs as a package).
- **Severity**: the advisory's own Red Hat rating, for every id it fixes. AlmaLinux: its summary prefix
  (`Critical:` 4, `Important:` 3, `Moderate:`, `Low:`). RHEL (review H1): the anchor of the advisory's classification
  reference (`https://access.redhat.com/security/updates/classification/#important`), stored per (binary, fix) like
  Alma's prefix; only an advisory with no rating (a bare classification link, 46 on RHEL 9) falls back to ITS OWN
  CVSS, else Medium (not shipped). Never the zip-wide CVSS of an id: that is the worst score ANY Red Hat product's
  advisory gave it (OpenShift, RHEL 7 ...). On the 2026-11-05 zip it shipped 619 of 846 RHEL 9 Moderate advisories and
  27 of 70 Low ones as High or Critical, and 10 Important ones as Medium; rated by Red Hat, RHEL and Alma now agree
  (rockylinux:9.3 and almalinux:9.2 flag the same 22 source rpms). **Id lists are per advisory, not per binary**: the
  rating applies to every CVE the advisory names, and Red Hat's OSV data attaches every CVE of an advisory to every
  binary it ships (RHSA-2026:42828, an httpd:2.4 update, lists the httpd CVEs under mod_http2 too, whose build only
  moved with the module). So a binary's id list can name CVEs its own code never had: the list is inflated, but the
  row decision (this binary is below a build Red Hat shipped as a security fix, rated by Red Hat) and the count of
  findings (per source rpm, not per CVE) are right.
- **Module streams**: a modular fix (`.module_el9...`, Red Hat's `.module+el9...`) carries the `name:stream` tokens
  of its advisories' summaries (`php:8.1`; `virt:rhel` and `virt-devel:rhel` for a two-module advisory), merged over
  every advisory naming that (binary, fix). The app compares a modular row only with a modular build of the same
  stream (the host's MODULARITYLABEL), a plain row only with a plain build; with no label or no stream it needs the
  same upstream major.minor. So a php:8.2 host never meets a php:8.1 or php:8.3 row.
- **Module builds (review M1, S6).** A modular release is `<n>.module+el8.10.0+<build id>+<context>.<z>`; the build id
  is the BUILDER's counter, not the package's. `rpmver.match_compare(a, b, rebuild)` (meshTerm's
  `RpmVersion.matchCompare`, shared vectors `tests/fixtures/rpm-module-match.txt`) compares two modular builds first
  WITHOUT `+<build id>+<context>` (version, the release up to and including the dist `module+elX.Y.Z`, Red Hat's
  z-stream `module+el9.3.0.z` and the layered `module+el8dsrv` / `module+el8pki` too, then the `.z` counter after the
  context). When that is equal (the same spec built twice), it depends on the host:
  - **Own vendor** (`rebuild=False`: a RHEL host on `rhel-*`, an AlmaLinux host on `alma-*`): the full EVR decides, ids
    included, so a REBUILD-ONLY fix is found. Red Hat rebuilt buildah `2:1.33.8-4` with no version or release change
    (`+22283+6d6d094a`, RHSA-2024:6969, then `+22346+28c02849`, RHSA-2024:8038, Important); skopeo and podman too. On
    the 2026-11-05 zips such same-spec groups are 240 (binary, fix) groups in rhel-8, 19 in rhel-9, 468 in alma-8 and
    51 in alma-9 (shipped rows); before S6 every rpm comparison ignored the ids and hid them all. The ids are taken
    out FIRST so the dist part never misorders content: rpm alone sorts Red Hat's 2019 Judy
    `1.0.5-18.module+el8+2765+cfa4f87b` above the 8.9 build `+el8.9.0+19449` (2765 against 9) and would flag every RHEL
    8 host with mariadb:10.3 forever.
  - **Rebuild host** (`rebuild=True`: a Rocky Linux host on `rhel-*`; the app decides by /etc/os-release ID, the golden
    cases by their `host`): equal. Rocky rebuilds Red Hat's specs with its own ids: httpd:2.4 `+1842+4a9649e8.2` ..
    `+2061+8d03fdec.5` (below Red Hat's `+22196+d82931da.2`), then `+40045+6ce8579b.6` .. `+40402+af9563a3.13` (above
    Red Hat's `+24521+219dcfc5.9`; rockylinux/rockylinux:8, 2026-11-05). Compared with the ids, an up-to-date low-id
    build looks behind forever and a stale high-id one (`.6` against Red Hat's `.9`) is never flagged. Red Hat's OSV
    data carries no module version (no `rpmmod` purl qualifier, no CSAF product id; checked on the 2026-11-05 zip), so
    a Rocky build of the same spec cannot be told from Red Hat's fix or an older build. Counting that tie as affected
    was measured and refused: the up-to-date Rocky 8 golden then flags nodejs (`+40175+15dc0b4a` IS Rocky's rebuild of
    RHSA-2026:8339's `+24197+1602b452`) and mod_http2, with nothing to install. **The cost**: a Rocky host is not
    flagged for a Red Hat rebuild-only fix (buildah above) until Red Hat ships a new version or release.
  - **Alma's mailman:2.1 (known, bounded).** Alma's records list three builds of mailman 2.1.29-12 on 8.5:
    `+26+48d4c9ee.2`, `+2601+e8845b76.1` and `+2602+327eb9f3.2` (ALSA-2021:4826 names all three as its fix, ALSA-2021:4916
    the two `.2` ones). Id 26 is below 2601 though its `.2` is above `.1`, the one inversion of id and content order in
    alma-8 (plain rpm order would flag a host on `+26` for the `.1` fix). The stripped comparison gets that pair right;
    against `+2602+327eb9f3.2` the two are the same spec and the ids decide, so a host on `+26+48d4c9ee.2` is flagged for
    CVE-2021-42096, -42097 and -44227 although ALSA-2021:4916 lists its build as a fix. The data cannot say whether `+26`
    is a parallel build or an older one (the contexts differ, as they do for buildah's real rebuild); one binary, one
    stream, on an end-of-life minor's build. Accepted.
- **No archive, no baseline, no published check** (as Alpine): the repositories' metadata are not fetched. The
  golden images were checked by hand instead: every binary they flag had a candidate at or above the fix in the
  image's own repositories (`dnf repoquery`, 2026-11-05), except Rocky's libcap above (the vendor lag).
- **Dates**: a row's date is the earliest `published` of the records naming it. Red Hat's `published` is often the
  day its records were CONVERTED to OSV, not the advisory's (RHSA-2003:315 says 2024-09-12), so it is good for the
  "fix older than 7 days" kernel rule and for "before the capture" on a capture-day golden, but never for a backdated
  golden (a `capture` in the past would silently drop every old advisory converted later; review L6). The same date
  is the fix's `publishedDate` in the file (S7c). On **alma-*** it is the ALSA errata's issue date (date-only
  midnight stamps; every one of the 6,393 records in the 2026-11-05 zip is dated in its id's year or the next). On
  **rhel-*** it is NOT reliably the errata date: 10,753 of 24,010 records in the same zip carry a 2024 conversion
  day (RHSA-2019:* dated 2024-09), so an old fix can read as "published" in 2024. It is kept (the kernel rule and
  ordering still use it); the app does not show a fix date on rhel-* hosts.
- **Fit to the cap**: a file over 600 KB keeps the newest N fixes per (binary, module stream), the largest N of 16,
  12, 10, 8, 6, 5, 4, 3 that fits. A host below an older fix is below every newer one, so no finding is lost; it lists
  fewer CVEs and can show a lower severity. Logged and counted. None needs it since review H1: rhel-8 was 850 KB with
  the zip-wide CVSS (pruned to 6 per binary), and is 486 KB (21% under the cap) rated by Red Hat; the S7c fix dates
  add 13 bytes per fix (about 532 KB, 13% under, estimated from serial 5). Any release file
  within 5% of the cap warns in the build record (`CAP_HEADROOM_WARN`, review L1).
- **Golden cases** (`builder/golden/*.rpm.tsv`): the app's Pro probe rpm listing from stock `almalinux:9` (9.8, the
  EL false-positive gate: `exact: []`), `almalinux:9.2` (July 2023), `rockylinux:9` (the library image, 9.3) and
  `rockylinux/rockylinux:9` (9.8, months behind) against rhel-9; `rockylinux/rockylinux:8` (8.10) upgraded with the
  httpd:2.4 and nodejs:20 modules installed (`exact: []` on rhel-8, the Rocky module gate) and with httpd pinned at
  Rocky's `+40045+6ce8579b.6` (`exact: [httpd]`); plus two SYNTHETIC php:8.2 module listings for the
  stream rule. Rows dated before the capture count, so the frozen images never drift; 3 or more unexpected
  source rpms fail.

**Adding a release** (every Ubuntu interim, every six months; the next is 27.04), in one pull request:

1. Add it to `RELEASES` in `builder/osvfeed.py` and to the `allow` set in the sign job of
   `.github/workflows/build.yml` (`tests/test_workflow.py` fails while the two differ).
2. Give it a minimum in `gates/minimums.json` (the build refuses a release without one). Its first build has no
   previous count, so that minimum is its only row floor.
3. A new Debian release also needs `build.py baseline --release <key>`.
4. Its end-of-life dates in `builder/eol.py` (`tests/test_eol.py` fails without them).

**Dropping a release** (an end-of-life interim), in one pull request:

1. Remove it from `RELEASES`, from the sign job's `allow` set and from `gates/minimums.json`.
2. Add it to `RETIRED_RELEASES` in `builder/osvfeed.py` and to the sign job's `retired` set (the test keeps the
   two equal). Without this the build fails: a release missing from the previous build's manifest must be
   either built or retired, so one cannot vanish by mistake.
3. The next build publishes no entry for it. Its last file stays on Pages only as a carry-over of the two builds
   before (the sign job allows a retired release's files only when a `builds/` record names them with that
   sha256), then ages out. Once a build has published without it, it can be removed from both retired lists.

`tests/test_workflow.py` (`test_retiring_a_release_end_to_end`) runs these steps against the sign job's check.

The rules (plan section 3), in order, with every count in the build log:

1. Range shapes: ECOSYSTEM, alternating introduced/fixed. Anything else, or an Ubuntu `availability` we have not
   seen, is an unknown shape and **fails that release** (see fail-soft below).
2. Unfixed rows are dropped. Withdrawn records are skipped. Livepatch, Legacy add-on and BlueField rows never
   ship; Ubuntu Pro rows go only to the `-esm` files.
3. Fixed values that are date-shaped or not valid Debian versions are rejected.
4. **Release-baseline cut**: fixed <= the release-day version is dropped (it never matches a host of that
   release). Ubuntu: the release pocket (frozen on release day). Debian: `builder/baselines/`.
5. A surviving fixed value whose leading number matches nothing the source has had is rejected (an ecosystem
   with 0.5% or more rejected fails all its releases).
6. **Published check**: the highest version across every pocket (`<codename>`, `-updates`, `-security`) and
   component must be >= fixed. ESM rows skip it (the ESM archive needs a subscription token). Each suite's
   `InRelease` must carry at least one valid signature from the distro keyring pinned in `keys/archive/`, and no
   bad one (checked with `gpgv`, apt's rule), before any of its Sources digests is trusted. Replays are refused
   two ways: an expired `Valid-Until` (Debian -security and -updates carry one) fails the release, and so does
   a `Date` older than the one recorded for that suite (the build record's `inrelease`, a per-suite high-water
   that never goes down; Ubuntu's pockets have no Valid-Until, so this is their defence). A failed release is
   carried forward (fail-soft). An archive version
   our strict parser refuses is skipped and counted.
7. Severity per CVE: the package's own Ubuntu priority, else the record's, else CVSS 3.x/4.0, else Medium
   (Ubuntu); CVSS, else High when a DSA/DLA naming that CVE ships the fix, else Medium (Debian). Only High and
   Critical ship.
8. Kernel sources (`linux`, `linux-*` except firmware and the like) fold to counts.

More gates, per release:

- **Row counts** (`row_gate`): at least `max(gates/minimums.json, half the previous count)`, and within +-30% (or
  25 rows) of the previous build. A reviewed exception is an entry in `gates/overrides.json` (`release`, `min`,
  `max`, `expires`, `reason`): while unexpired it replaces both rules with `[min, max]`; expired entries are
  ignored. Adding one is a commit on main, which is the review.
- Each file under 600 KB, and its schema (`check_release_body`).
- The **golden fixtures** in `builder/golden/expected.json`: stock `ubuntu:24.04` and `debian:12` images and a
  June 2023 `debian:12.0`. A case counts a row only when its fix date is before the capture date and its fixed
  version was in the archive at capture time (the case's `.archive.tsv`, from snapshot.ubuntu.com /
  snapshot.debian.org). Errors: an expected source not flagged (a regression that drops a real fix), or a hit on
  a source the frozen archive does not list. An EXTRA hit on an `exact` case is a warning: every counted row is
  already pinned to the archive at capture, so an extra one can only come from OSV re-rating an old CVE (the
  stock images carry pending Medium fixes, such as pcre2, that could become High) or adding ids. Freezing
  severities and ids instead would stop the gate from noticing a re-rated row that the builder then drops.
  Extra hits still FAIL when they cover 3 or more sources, or when any of them was rated High by a heuristic
  rule (`ubuntu package priority`, `dsa/dla exists -> high`) rather than a published score; every shipped row
  records each id's rule in the intermediates (`rules`).

The intermediates (`--work`, the `intermediates` CI artifact) hold every shipped row with its publish date and
every dropped row with its reason.

**Fail-soft.** The curated rules must keep refreshing (the app hides every finding from a feed older than 7
days), so no S2 problem stops a build. A release whose archive, OSV zip or gates fail is not rebuilt: the
manifest carries forward its last published entry (same file, sha256, bytes and rows, from the newest `builds/`
record that names it, the file re-fetched from the live site and checked), and the UNSIGNED build record gets
`stale: {release: {since, reason}}` (`since` is when it first failed). The manifest format is unchanged. If the
whole S2 step fails, every release is carried forward. A release with nothing to carry is left out, and the
record says `omitted`. A release stale for more than 7 days (from its `since`) is also left out of the manifest,
so the app's 7-day freshness rule holds per release: it shows nothing for that release rather than old data.
Upstream-shaped failures (network, signature, digest, archive or OSV data, gates) are plain `stale`. Any other
exception is a builder BUG: it is carried forward all the same (curated keeps publishing), but the record marks
it `bug: true` with its `traceback` and lists it in `bugs`, and the workflow's last job (`builder-bug`, after
deploy and record) fails the run with an `::error::` annotation. Only a broken committed configuration (`gates/`, a missing baseline, a release dropped
without being retired) and an invalid curated file still fail the build.

Signature (minisign, prehashed Ed25519), trusted comment exactly:

```
vulnfeed=host-vulns version=<serial> date=<YYYY-MM-DD> commit=<sha>
```

`version=` is the second token (meshDeckShared `SignedArtifactContract(label: "vulnfeed", kind: "host-vulns")`),
so a recipes, catalogue or channel signature never passes as a feed. `date` is the date of `generated`.

## Changing a rule

1. Branch, edit `curated/curated.json`.
2. `python3 builder/validate_curated.py && python3 -m unittest discover -s tests -t tests`
3. Pull request for the record, then merge. The next build (00:20, 06:20, 12:20 or 18:20 UTC) publishes it, or run
   `Build vulnfeed` by hand (Actions > Build vulnfeed > Run workflow).

The floors are set by hand. "Recommended" rules never enter the app's pill; they show only in the detail sheet.

## Local build

```sh
python3 builder/build.py build --commit "$(git rev-parse HEAD)" --out out --cache cache --work work
python3 scripts/sign.py sign --manifest out/v1/manifest.json --key ~/.config/meshterm-vulnfeed/feed.key \
  --commit "$(git rev-parse HEAD)"
python3 scripts/sign.py verify --manifest out/v1/manifest.json --role feed --require-commit
```

Needs `python3` (stdlib only) and `minisign`. The tests generate throwaway keys and never touch the real ones, and
never touch the network. A full build downloads about 900 MB of OSV zips (Ubuntu's is 0.8 GB) and about 100 MB
of Sources into `--cache`, and takes 3 to 5 minutes; `--offline` re-runs from the cache. `--offline` needs a
cache that already holds each suite's signed `InRelease` (it re-verifies them), so run once online first: a
cache from before InRelease verification only has unsigned `Release` files and every release fails offline.

- `build.py baseline --release debian-12` re-generates a Debian baseline (only needed for a new release).
- `build.py golden-archive` re-generates the golden `.archive.tsv` files (only when a fixture changes).

## The workflow (`.github/workflows/build.yml`)

Builds are `workflow_dispatch` runs fired at 00:20, 06:20, 12:20 and 18:20 UTC by a timer on James's Linux box
(`trigger/`, install with `bash trigger/install.sh`), because GitHub ran its schedule 3.5 to 8.6 hours late. The
workflow's own schedule (`40 */2 * * *`) is a fallback: its `due` job builds only when the live feed is over 7 h old. No pull-request trigger. `permissions: {}` by default.

| job | permissions | what |
|---|---|---|
| build | `contents: read` | tests, builder, gate; the OSV/archive download cache (`actions/cache`, keyed by its contents); uploads the unsigned site, the build record and the intermediates |
| sign | `contents: read`, `actions: read`; environment `vulnfeed-signing` | inline shell and `python3 -I` only (no repository script): checks the environment is main-only, re-checks the artifact (the committed curated file; every release entry names an existing `v1/r/<allowlisted release>-<16hex>.json` with matching sha256 and bytes; the fixed `sources` shape; no other files), signs with `VULNFEED_MINISIGN_KEY`, verifies |
| deploy | `pages: write`, `id-token: write` | `actions/deploy-pages` |
| smoke | `contents: read` | fetches the live pair and verifies it, then each release file's sha256 (CDN lag is a warning) |
| record | `contents: write` | commits `builds/<serial>.json` to main (history, and repo activity so GitHub keeps the schedule) |
| builder-bug | none | only when the build record lists a builder bug: runs after deploy and record and fails the run with an `::error::` |

Every action is pinned by commit SHA (the ones meshterm-recipes uses).

## GitHub setup checklist (NOT done yet)

- [ ] Create the PUBLIC repository `AG-Studio-Apps/meshterm-vulnfeed` and push `main`.
- [ ] Settings > Pages: Source = **GitHub Actions**.
- [ ] Settings > Environments: create **`vulnfeed-signing`**. Deployment branches and tags = **Selected branches
      and tags**, with the single rule `main`. **No required reviewer** (it signs unattended). Or run:

      ```sh
      R=AG-Studio-Apps/meshterm-vulnfeed
      gh api -X PUT repos/$R/environments/vulnfeed-signing \
        -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
      gh api -X POST repos/$R/environments/vulnfeed-signing/deployment-branch-policies -f name=main
      ```
- [ ] Add the environment secret **`VULNFEED_MINISIGN_KEY`** = the whole feed secret key file
      (`gh secret set VULNFEED_MINISIGN_KEY --env vulnfeed-signing -R $R < ~/.config/meshterm-vulnfeed/feed.key`).
      No password secret: the feed key has none.
- [ ] Make sure the `github-pages` environment allows `main` (the default).
- [ ] If `main` gets branch protection, let `github-actions[bot]` push (the record job commits `builds/`), or the
      record job fails and the 60-day schedule timer is no longer reset.
- [ ] Run `Build vulnfeed` once by hand and check the smoke job, then confirm the schedule fires.
- [ ] meshTerm: create the label **`vulnfeed`** in `AG-Studio-Apps/meshTerm` (`gh label create vulnfeed -R
      AG-Studio-Apps/meshTerm`), or the alert cannot file.
- [ ] Freshness alert: `bash alert/install.sh`, try `~/.local/lib/vulnfeed-freshness/run.sh` (dry run), then
      `echo VULNFEED_ALERT_DRY_RUN=0 > ~/.config/vulnfeed-freshness.env` and
      `systemctl --user daemon-reload && systemctl --user enable --now vulnfeed-freshness.timer`.
- [ ] Move the emergency key and its passphrase offline; delete the box copies (see `keys/README.md`).

## Freshness alert (`alert/`)

`check.py` fetches `v1/manifest.json` and `.minisig` from the live site, verifies them against the installed
copy of `keys/`, checks the curated file's sha256, and files ONE issue in the private `AG-Studio-Apps/meshTerm`
(label `vulnfeed`) when `generated` is more than 24 hours old, the pair does not verify, or a file is missing.
It also reads the build record of the live serial as COMMITTED on main (`builds/<serial>.json` on
raw.githubusercontent.com; committed, not published, because the record is unsigned and the sign job allows no
extra files on Pages) and reports `stale-release` when any release has been carried forward for more than 48 h,
`builder-bug` at once when the record lists a builder bug, or `fetch-record` when that record is missing. It comments again only when the problem changes or once a day,
flags an emergency-key signature, and closes the issue when the feed recovers. Dry run unless `VULNFEED_ALERT_DRY_RUN=0`. The timer runs at 06:40 and 18:40
UTC.

## Keys and incidents

- The **feed key** (`965BA616AC0D4DFC`) signs every build, unattended, from the main-only environment. Its blast
  radius is bounded: the feed carries no commands, the app re-checks names against the host, and the app
  hides findings from a feed older than 7 days.
- The **emergency key** (`299EE7D96076CF7D`) is offline and passworded. If the feed key leaks: delete the
  `VULNFEED_MINISIGN_KEY` secret (the schedule then fails closed at the sign step and the alert fires), build
  locally, and sign with `scripts/sign.py sign --role emergency --key <offline key>`. Publishing an emergency
  signature through the workflow is not built yet (see TODO), and the app's pinned keys change only with an app
  release.
- Rotation touches four places that must move together: `keys/`, the key ids in `build.yml`, the alert's
  installed keys (re-run `alert/install.sh`), and the app's `VulnFeedTrust`.

## TODO

- An EL repository metadata published check (repomd.xml is GPG-signed; primary.xml would also give the binary to
  source rpm map); an APKINDEX published check for Alpine (needs RSA verification); the next Ubuntu interim (27.04) in `RELEASES` and the sign job's
  allowlist when it ships.
- An emergency publish path in the workflow (a committed `manifest.json.minisig` mode, as in meshterm-recipes).
