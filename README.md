# meshterm-vulnfeed

The signed host vulnerability feed meshTerm reads for "Security updates" (meshTerm
`docs/plan-host-cve-scanner.md`). Plain static JSON on GitHub Pages, rebuilt twice a day.

**Stage S2 (this state): curated rules plus OSV release files for dpkg releases.** The manifest carries the
hand-written Tailscale rules and one release file per Ubuntu / Debian release (`builder/osvfeed.py`). Alpine
(S4) and the rpm family (S5) come later.

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
  cache; `builder/dpkgver.py` Debian version comparison; `builder/cvss.py` CVSS 3.x and 4.0 scores.
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
                               "sha256": "8dcc0c17...", "bytes": 38955, "rows": 892}, "...": {}},
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
  every file under 600 KB; no unexpected file, no symlink; the curated file re-validates.

## Release files (`v1/r/`)

```json
{"release":"ubuntu-24.04","format":"dpkg","keyedBy":"source",
 "pkgs":{"apt":[["0","2.8.4ubuntu0.1",3,["CVE-2026-109518"]]]},
 "kernel":{"linux-aws-6.8":[["0","6.8.0-1040.42~22.04.1",3,57,"2026-10-30"]]}}
```

A package row is `[introduced, fixed, severity, ids]` (severity 3 High, 4 Critical; ids are the High/Critical
CVEs fixed there); a kernel row is `[introduced, fixed, maxSeverity, count, publishedDate]`. Keyed by SOURCE
package: hosts match `${source:Package}` / `${source:Version}`.

Releases (`RELEASES` in `builder/osvfeed.py`, and the sign job's allowlist): `ubuntu-20.04`, `-22.04`, `-24.04`,
`-26.04`, `-26.10` (the current interim; 25.10 is end of life), `ubuntu-<lts>-esm` (the `Ubuntu:Pro:<lts>` rows,
for hosts with Ubuntu Pro attached), `debian-11`, `-12`, `-13`.

**Adding a release** (every Ubuntu interim, every six months; the next is 27.04), in one pull request:

1. Add it to `RELEASES` in `builder/osvfeed.py` and to the `allow` set in the sign job of
   `.github/workflows/build.yml` (`tests/test_workflow.py` fails while the two differ).
2. Give it a minimum in `gates/minimums.json` (the build refuses a release without one). Its first build has no
   previous count, so that minimum is its only row floor.
3. A new Debian release also needs `build.py baseline --release <key>`.

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

The intermediates (`--work`, the `intermediates` CI artifact) hold every shipped row with its publish date and
every dropped row with its reason.

**Fail-soft.** The curated rules must keep refreshing (the app hides every finding from a feed older than 7
days), so no S2 problem stops a build. A release whose archive, OSV zip or gates fail is not rebuilt: the
manifest carries forward its last published entry (same file, sha256, bytes and rows, from the newest `builds/`
record that names it, the file re-fetched from the live site and checked), and the UNSIGNED build record gets
`stale: {release: {since, reason}}` (`since` is when it first failed). The manifest format is unchanged. If the
whole S2 step fails, every release is carried forward. A release with nothing to carry is left out, and the
record says `omitted`. Only a broken committed configuration (`gates/`, a missing baseline, a release dropped
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
3. Pull request for the record, then merge. The next scheduled build (05:10 or 17:10 UTC) publishes it, or run
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
of Sources into `--cache`, and takes 3 to 5 minutes; `--offline` re-runs from the cache.

- `build.py baseline --release debian-12` re-generates a Debian baseline (only needed for a new release).
- `build.py golden-archive` re-generates the golden `.archive.tsv` files (only when a fixture changes).

## The workflow (`.github/workflows/build.yml`)

Schedule 05:10 and 17:10 UTC, plus `workflow_dispatch`. No pull-request trigger. `permissions: {}` by default.

| job | permissions | what |
|---|---|---|
| build | `contents: read` | tests, builder, gate; the OSV/archive download cache (`actions/cache`, keyed by its contents); uploads the unsigned site, the build record and the intermediates |
| sign | `contents: read`, `actions: read`; environment `vulnfeed-signing` | inline shell and `python3 -I` only (no repository script): checks the environment is main-only, re-checks the artifact (the committed curated file; every release entry names an existing `v1/r/<allowlisted release>-<16hex>.json` with matching sha256 and bytes; the fixed `sources` shape; no other files), signs with `VULNFEED_MINISIGN_KEY`, verifies |
| deploy | `pages: write`, `id-token: write` | `actions/deploy-pages` |
| smoke | `contents: read` | fetches the live pair and verifies it, then each release file's sha256 (CDN lag is a warning) |
| record | `contents: write` | commits `builds/<serial>.json` to main (history, and repo activity so GitHub keeps the schedule) |

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
or `fetch-record` when that record is missing. It comments again only when the problem changes or once a day,
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

- S4 (Alpine) and S5 (rpm) release files; the next Ubuntu interim (27.04) in `RELEASES` and the sign job's
  allowlist when it ships.
- An emergency publish path in the workflow (a committed `manifest.json.minisig` mode, as in meshterm-recipes).
