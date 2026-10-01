# Six internal design docs ship inside `Occulta.app`, regressing the 1.10.2 bundle-contents fix

**Status: fixed on `v2.0.0/exclude-design-docs-from-bundle`, 2026-10-01.** Tracker entry: Bug 154,
`Docs/Features/Secure Mode/bugs.md`. Audit record: `Docs/Audit/SECURITY_CHECKLIST.md` §6, "Shipped
bundle contents".

## Symptom

A Release archive of `develop` at `3319fd7` (the v1.11.1 merge) had six Markdown files at the top
level of `Occulta.app/`:

| File (under `Occulta/Features/`)       | Size at `v1.11.1` | Added      |
|----------------------------------------|-------------------|------------|
| `Vault/BEK_LAYERING_REFACTOR.md`       | 638 B (stub)      | 2026-08-28 |
| `SecureMode/AT_REST_LAYERING.md`       | 599 B (stub)      | 2026-09-02 |
| `Vault/STORAGE_LAYERING.md`            | 1.2 KB (stub)     | 2026-09-03 |
| `Vault/RECOVERY_BUFFER_LAYERING.md`    | 104 KB            | 2026-09-04 |
| `Vault/VAULT_KEY_LAYERING.md`          | 140 KB            | 2026-09-04 |
| `SecureMode/PASSPHRASE_LAYER_KEYS.md`  | 17 KB             | 2026-09-10 |

The three stubs are "superseded, see X" pointers. Their names still say what they are, and they name
the documents that hold the design.

## Which releases shipped it

Each of these was checked by reading the tag's tree against its exception set. Only `develop` at
`3319fd7` was actually archived.

- **`v1.11.1`** and **`v1.11.0`**: all six, none excluded.
- **`v1.10.3`** (`92e3e6e`, 2026-09-02): `BEK_LAYERING_REFACTOR.md` only, not excluded. At that tag
  it was the full 26 KB BEK/recovery layering design compiled from the 2026-08-26/27 security
  review, not today's stub.

## Why it matters

This is the same harm recorded in §6 for 1.10.2. The bundle is identical on every install, so it
does not show whether this user has Secure Mode configured. But it hands an examiner or coercer the
app's at-rest layering and duress-depth key design, which contradicts the forensic-trace invariant.
The threat model assumes the adversary knows the app. It does not assume the app hands them the
design docs.

## Root cause

`Occulta/` is a file-system-synchronized root group, so Xcode copies every non-source file under it
into the bundle unless the Occulta target's exception set
(`DE8B24C72EEEBB4300B83B51`) lists it in `membershipExceptions`. The 1.10.2 fix listed the fifteen
docs that existed then. Nothing failed when a sixteenth arrived, so each new doc added next to the
code shipped by default.

## Fix

1. All six are added to `membershipExceptions`. None of the paths contains `+` or a space, so
   none needs quoting. A sweep of every `.md`/`.html` under `Occulta/` against the list found no
   others missing. `ShareExtension/`, `OccultaPreview/` and `Assets/` contain none.
2. **Guard, chosen over the alternatives on 2026-10-01:** `OccultaTests/BundleContentsTests.swift`.
   The test target runs hosted in `Occulta.app` (`TEST_HOST`), so the test walks `Bundle.main`,
   including `PlugIns/`, and fails on any `.md` or `.html`, naming each file. A companion test
   asserts that the host really is `Occulta.app` with both appexes embedded, so a host or embedding
   change cannot make the scan pass on an empty tree. Membership exceptions do not vary by
   configuration, so the Debug bundle carries the same resources as Release. The guard needs no
   Enclave, so it runs on every PR in CI.

   Alternatives considered:
   - A Run Script phase would catch it earlier, at build time. But
     `ENABLE_USER_SCRIPT_SANDBOXING = YES` means declaring the bundle as an input or turning off
     sandboxing for the target.
   - A CI archive step would check the real artifact, at the cost of a second full build per PR, and
     it leaves local builds unguarded.
   - Moving the docs out of `Occulta/` would remove the cause. But it breaks links and splits docs
     from their code, and a doc added next to code later would still regress silently without a
     guard.

## Verification

- With the six exclusions reverted, `BundleContentsTests` fails and lists exactly the six files.
  With them restored, it passes.
- Re-archive (`xcodebuild … -configuration Release -destination 'generic/platform=iOS'
  CODE_SIGNING_ALLOWED=NO archive`): `find` reports zero `.md` and zero `.html` anywhere in the
  `.xcarchive`, both appexes included. `Occulta.app/` holds the binary, `Info.plist`, `PkgInfo`,
  `PlugIns/`, two app icons, `Assets.car`, `eff_large_wordlist.txt` and `features.plist`.
  `ShareExtension.appex` holds its binary and `Info.plist`; `OccultaPreview.appex` adds
  `Base.lproj`.

## What this does not undo

A device running v1.10.3, v1.11.0 or v1.11.1 keeps the files until it updates to a build with this
fix, because an update replaces the whole bundle. Nothing the app can do at runtime removes them,
since the bundle is read-only.
