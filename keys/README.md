# Vulnerability feed signing keys

Two minisign (Ed25519) key pairs, generated 2026-11-05 with `minisign 0.11` (prehashed `ED` signatures, which
meshDeckShared's `MinisignVerifier` accepts). They are NOT the recipes or template catalogue keys: a recipes or
channel signature can never pass as a feed, and a feed signature never passes as recipes.

| role | file | key id | public key (second line of the .pub, what the app embeds) |
|---|---|---|---|
| primary (the unattended "feed" key, CI signs with it) | `vulnfeed-feed.pub` | `965BA616AC0D4DFC` | `RWT8TQ2sFqZblqBak2SdigoVlOwdXXvCTy8CARxTtjk1xaqfHt+LRFhO` |
| emergency (offline) | `vulnfeed-emergency.pub` | `299EE7D96076CF7D` | `RWR9z3Zg2eeeKRHvl+KuKGrxuxs+ys5om4CFRC9ZR25dmCVKJIw9/OQI` |

App side (meshDeckShared `MeshDeckSigning`):

```swift
SignedArtifactContract(label: "vulnfeed", kind: "host-vulns", trustedKeys: [
    try TrustedSigningKey(base64: "RWT8TQ2sFqZblqBak2SdigoVlOwdXXvCTy8CARxTtjk1xaqfHt+LRFhO",
                          role: .primary, expectedKeyID: "965BA616AC0D4DFC"),
    try TrustedSigningKey(base64: "RWR9z3Zg2eeeKRHvl+KuKGrxuxs+ys5om4CFRC9ZR25dmCVKJIw9/OQI",
                          role: .emergency, expectedKeyID: "299EE7D96076CF7D"),
])
```

The trusted comment the feed key signs is exactly:

```
vulnfeed=host-vulns version=<serial> date=<YYYY-MM-DD> commit=<40 hex>
```

`version=` is the second token, as `SignedArtifactContract.signedVersion(in:)` requires. The manifest carries the
same number twice, as `serial` and as a top-level `version` (so `SignedArtifactVerifier.jsonVersion(of:)` works
with no `bodyVersion:` argument). An emergency signature may omit ` commit=`.

## Where the secret keys are

- Feed key: **no password** (minisign `-W`), because CI signs unattended. It lives only as the
  `VULNFEED_MINISIGN_KEY` secret of the `vulnfeed-signing` environment, plus an offline recovery copy.
- Emergency key: **password-protected**, kept offline with its passphrase in the password manager.

Neither secret key is ever committed; `.gitignore` refuses `*.key`.

## Rotation

Rotating a key touches FOUR places that must move together: the `.pub` here, the key ids pinned in
`.github/workflows/build.yml` (`FEED_KEY_ID`, `EMERGENCY_KEY_ID`), the alert's copy (it reads `keys/` from this
repository), and the app's pinned keys (meshTerm `VulnFeedTrust`).
