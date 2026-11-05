# Distro archive keyrings

The builder (`builder/osvfeed.py verify_inrelease`) verifies every suite's `InRelease` with `gpgv` against these
keyrings before it trusts any Sources digest. Pinned 2026-11-05:

| file | from | sha256 |
|---|---|---|
| `ubuntu-archive-keyring.gpg` | Ubuntu `ubuntu-keyring` 2023.11.28.1, `/usr/share/keyrings/ubuntu-archive-keyring.gpg` (Archive Automatic Signing Keys 2012 and 2018) | `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31` |
| `debian-archive-keyring.gpg` | Debian `debian-archive-keyring` 2025.1 (the `debian:13` image), `/usr/share/keyrings/debian-archive-keyring.gpg` (archive, security and stable release keys for 11, 12 and 13) | `506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017` |

A suite passes when at least one signature is VALIDSIG from the keyring and none is BADSIG (apt's rule): the
release-day bookworm InRelease on snapshot.debian.org also carries a buster-key signature that this keyring no
longer has. Refresh these when a distro rotates its archive key (a new Debian release brings new keys) and
update the table in the same commit. The Debian keys expire 2029 to 2035.
