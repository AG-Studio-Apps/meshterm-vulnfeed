# meshterm-vulnfeed

The signed host vulnerability feed meshTerm reads for "Security updates" (meshTerm
`docs/plan-host-cve-scanner.md`). Plain static JSON on GitHub Pages, rebuilt twice a day.

**Stage S1 (this state): curated-only.** The manifest carries the hand-written Tailscale rules and an empty
`releases` object. The OSV builder (Ubuntu/Debian release files) is S2: its seam is `build_releases()` in
`builder/build.py`.

## Layout

```
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/manifest.json          (+ .minisig, the only signed file)
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/curated-<sha256-16>.json
https://ag-studio-apps.github.io/meshterm-vulnfeed/v1/r/<release>-<sha256-16>.json   (S2)
```

- `curated/curated.json`: the rules, reviewed in pull requests. `curated/curated.schema.json` documents them;
  `builder/validate_curated.py` is authoritative. A rule is a closed set of fields: `id`, `product` (only
  `tailscale`: a product needs a probe compiled into the app), `below` and `fixedIn` (plain `N.N.N`),
  `severity` (1-4), `kind` (`security`, the default, or `recommended`), `ids`, `title`, `url` (https),
  `appliesTo` (`any` or `tailnet`). **The feed never carries a command or a recipe**: any other field is
  refused, so a compromised feed key can only add or hide a finding.
- `builder/build.py`: writes `out/v1/manifest.json` and the content-addressed files, then gates them.
- `builder/manifest.schema.json`: the manifest, as documentation (`check_manifest()` is authoritative).
- `scripts/sign.py`: local signing and verification (CI does not run it to sign).
- `keys/`: the two public keys the app pins. See `keys/README.md` for the ids and the Swift snippet.
- `builds/<serial>.json`: one per published build (the manifest, the files carried, the build log),
  committed by CI.
- `alert/`: the external freshness alert (a systemd user timer on the maintainer's machine).

## The manifest

```json
{"schema": 1, "serial": 12, "version": 12, "generated": "2026-11-05T05:10:00Z",
 "sources": {}, "releases": {},
 "curated": {"file": "curated-25abfc9f67145d28.json", "sha256": "25abfc9f...aa63b"}}
```

- `serial` is the number in the trusted comment; `version` repeats it so `SignedArtifactVerifier` reads it
  with no `bodyVersion:` argument.
- Serial = the highest `builds/<serial>.json` + 1, floored by the live manifest's serial (a deployed build whose
  `builds/` commit was lost must never have its serial reused: devices refuse the same serial with other bytes).
- Every file the manifest names is checked by its sha256. The files of the previous 2 builds are carried
  forward (fetched from the live site and checked against their `builds/` record), so 3 builds stay live.
- Gate before signing: the manifest's exact shape, canonical bytes, under 16 KB; every named file present and
  matching its sha256; every file under 600 KB; no unexpected file, no symlink; the curated file re-validates.

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
python3 builder/build.py build --commit "$(git rev-parse HEAD)" --out out
python3 scripts/sign.py sign --manifest out/v1/manifest.json --key ~/.config/meshterm-vulnfeed/feed.key \
  --commit "$(git rev-parse HEAD)"
python3 scripts/sign.py verify --manifest out/v1/manifest.json --role feed --require-commit
```

Needs `python3` (stdlib only) and `minisign`. The tests generate throwaway keys and never touch the real ones.

## The workflow (`.github/workflows/build.yml`)

Schedule 05:10 and 17:10 UTC, plus `workflow_dispatch`. No pull-request trigger. `permissions: {}` by default.

| job | permissions | what |
|---|---|---|
| build | `contents: read` | tests, builder, gate; uploads the unsigned site and the build record |
| sign | `contents: read`, `actions: read`; environment `vulnfeed-signing` | inline shell only (no repository script): checks the environment is main-only, re-checks the artifact against the committed curated file, signs with `VULNFEED_MINISIGN_KEY`, verifies |
| deploy | `pages: write`, `id-token: write` | `actions/deploy-pages` |
| smoke | `contents: read` | fetches the live pair and verifies it (CDN lag is a warning) |
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
It comments again only when the problem changes or once a day, flags an emergency-key signature, and closes
the issue when the feed recovers. Dry run unless `VULNFEED_ALERT_DRY_RUN=0`. The timer runs at 06:40 and 18:40
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

- S2: the OSV builder in `build_releases()`, with its gates (row counts +-30%, rejected versions under 0.5%,
  unknown range shapes = 0, the golden fixtures), and the sign job's `releases` check (it refuses a non-empty
  `releases` today).
- An emergency publish path in the workflow (a committed `manifest.json.minisig` mode, as in meshterm-recipes).
