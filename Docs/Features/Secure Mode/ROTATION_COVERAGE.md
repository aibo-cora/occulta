# Rotation Coverage — making the Model Coverage contract executable

**Status:** Scoping. No code written. Proposed 2026-08-16.
**Owner doc it extends:** [`SecureMode+RotationContract.md`](../../../Occulta/Features/SecureMode/SecureMode+RotationContract.md),
"Model Coverage" — this document does not replace that reasoning, it proposes making it enforceable.
**Register item:** supersedes F3 in `Docs/Audit/OPEN_LIMITATIONS.md`, and absorbs part of C1.

**Note on placement:** this file lives under `Docs/` deliberately. Anything under `Occulta/` is
inside an Xcode 16 file-system-synchronized root group and ships in the app bundle unless added to
`membershipExceptions` — see §6 of `Docs/Audit/SECURITY_CHECKLIST.md`, where sixteen internal
documents were found in a Release archive.

---

## The problem, stated as three lists

Key rotation stages a new local DB key, re-encrypts, commits, then deletes the superseded key.
Anything not re-encrypted in between is sealed under a key that no longer exists — permanently,
because the hybrid key needs a Secure Enclave half that is non-exportable.

Three separate lists must agree with reality, and each has failed:

| Level | The list | Failure |
|---|---|---|
| Type | which models get rotated at all | Bugs **75**, **76** — `Group` and `AppLayerConfig` missing from both paths |
| Field | which fields within a covered type | Bug **77** — `maxBundleVersion`, `deletionToken` missing from `reencryptAllFields` |
| Path | activation and deactivation are separate code | `Message.Draft` correct in activation from the start, absent from deactivation until 2026-08-14 |

Every instance failed **silently**, and the contract is right that this is by design rather than
bad luck: `reencryptAllFields` nils fields it cannot decrypt, read accessors have safe fallbacks,
`if let` swallows a missing key. The system degrades quietly for forensic reasons, and that
property — correct in itself — is exactly what hides this bug class.

## Why the current guard is not enough

The existing `EncryptedFieldCoverageTests` is well-built and its header is honest about the limit:
*"This cannot tell whether a new field needs re-keying; it forces the decision to be made."*

The gap is in how it is silenced. Its guidance ends *"Then add the name to the list in this test."*
Adding a name to a **test-only** list is the same act that silences the alarm — so the tripwire
proves *awareness*, not *coverage*. The behavioural round-trip is what proves coverage, and it is
updated by a second, separate human step. The lazy path survives: acknowledge the field, do not
rotate it, tests pass.

**Direct evidence that prose enforcement does not hold.** The contract's own enforcement table
(line 65) states `Message.Draft` has *"no name tripwire"*, and its "Adding a new model" section
(line 103) instructs the reader to add one. Commit `8a431ac` added it. The document that tracks
which models are enforced has drifted from the thing it tracks — which is the same failure mode as
the bugs it exists to prevent, one level up.

## What blocks full automation

`Mirror` on a SwiftData `@Model` enumerates every stored property but **erases every type to
`_SwiftDataNoType`** (documented at `EncryptedFieldCoverageTests.swift:23-26`). You cannot ask "is
this a `Data?`", so encrypted fields cannot be auto-discovered and name-keyed lists are forced.

The goal is therefore not to eliminate the list. It is to ensure there is **exactly one**, that
**production uses it**, and that it is checked against something load-bearing rather than against
another list.

---

## Design

### 1. Explicit decrypting and encrypting keys

`reencrypt(string:to:aad:)` (`Contact+Model+Reencrypt.swift:128`) takes the encrypting key as a
parameter but decrypts through `ciphertext.decrypt()` — the **ambient** extension, which builds
`Manager.Crypto()` and derives whatever the canonical key currently is.

So today: encrypting key explicit, **decrypting key implicit and global**.

That is why the ordering constraint *"must run before `commitStagedLocalDBKey()`"* exists, and it is
enforced only by a comment. If the commit ran first, `.decrypt()` would silently switch to the new
key, every field would fail, and `reencrypt(data:)` returns `nil` on failure — mass silent data
loss, reachable by reordering two lines. That is Bug 78's shape.

```swift
func rotateAll(decryptingKey: SymmetricKey,
               encryptingKey: SymmetricKey,
               aad: Data) throws
```

Three consequences beyond deduplication:

- **The ordering constraint becomes type-enforced** rather than comment-enforced.
- **It removes N×fields Secure Enclave derivations.** Every ambient `.decrypt()` re-derives the
  hybrid key — SE retrieval, ECDH, keychain read, HKDF. Rotation is the hottest path in the app and
  this is the cost profile behind Bug 74's `0x8BADF00D` watchdog kill. Directly advances **C2**.
- **The group-after-drafts ordering dissolves.** That constraint exists because `Group.readID()`
  decrypts with the ambient canonical key; with an explicit decrypting key it stops being
  load-bearing.

`Group.reencrypt(from:to:)` and `AppLayerConfig.reencrypt(from:to:)` — both added *later*, as the
Bug 75/76 fixes — already take two keys. `Contact.Profile` is the odd one out; the newer code
already reached this conclusion.

### 2. One field list per type, used by production

```swift
extension Contact.Profile: RotatableModel {
    static let rotatedFields: [String: RotationPolicy<Contact.Profile>] = [
        "givenName":        .clearing(\.givenName),
        "deletionToken":    .preserving(\.deletionToken),   // presence means "not deleted"
        "maxBundleVersion": .preserving(\.maxBundleVersion),
        …
    ]
    static let plaintextFields: Set<String> = ["encryptionScheme", …]
}
```

`reencryptAllFields` iterates `rotatedFields` instead of hand-assigning. The tripwire asserts
`rotatedFields.keys ∪ plaintextFields == Mirror(model)` names.

The win: **adding a name to the list now causes rotation**, rather than merely acknowledging it.
Awareness and coverage become the same edit. A typo'd key fails in both directions — the dictionary
gains an unknown name and `Mirror` gains an unaccounted one.

`RotationPolicy` carries the preserve-vs-clear decision so it cannot be skipped. That judgment stays
human — `deletionToken`'s presence carries meaning independently of its content, and nil-ing it
un-deletes contacts — but you cannot add an entry without typing `.clearing` or `.preserving`.

### 3. One type registry, checked against the schema

```swift
static let rotatableModels: [any RotatableModel.Type] = [ … ]

/// Every schema type absent from `rotatableModels`, with the key that seals it instead.
static let notRotated: [String: String] = [
    "VaultEntry":   "content under the vault key; only visibleThroughDepth is local-DB",
    "CustodyShard": "deriveShardCustodyKey — automatic shard ops run without user approval",
    …
]
```

The test asserts every type in `OccultaApp`'s `Schema([...])` literal appears in one or the other.
**That anchor is what makes this structural**: the schema is not a test fixture, it is the array the
app `fatalError`s without. It cannot be quietly forgotten the way a test list can.

The second table of the contract's Model Coverage section is the seed for `notRotated`, including
its warning that adding one of those to the rotation *"is as much a bug as leaving one of the above
out"*.

### 4. One walk, two call sites — with the value passes pulled out

Both paths call `rotateAll`. What must **not** move into it are the two genuine asymmetries, which
are not re-encryption at all:

- **Deactivation rewrites values.** `Manager+Security.swift:877-887` seals *computed*
  `visibleThroughDepth`, `globalTrusteeDepth` and `originDepth`. That is restore logic that happens
  to need encryption. Activation re-encrypts existing values instead.
- **The vault-entry nil policy is opposite in each direction.** Activation (`:574`) turns nil into
  sealed `hiddenData` — *"every entry must end up with a staged-key ciphertext — no silent skips."*
  Deactivation (`:917`) skips nil. Both deliberate, both documented, opposite.

Today re-encryption and value-rewriting are interleaved in one loop, which is why the two paths look
different enough that nobody noticed drafts were in one and not the other. Split them and the
rotation halves become **provably identical** — one function, two call sites — while the genuinely
different business logic sits visibly outside it, running after rotation under `encryptingKey`.

---

## Where it lives

```
Occulta/Features/SecureMode/
  RotationRegistry.swift        rotatableModels, notRotated, rotateAll(decryptingKey:encryptingKey:aad:)
  RotationPolicy.swift          .clearing / .preserving, generic over the model

Occulta/Data Models/
  Contact+Model+Reencrypt.swift rotatedFields — next to the properties it names
  Group+Model.swift             ditto
  …

OccultaTests/SecureMode/
  RotationRegistryTests.swift        schema-vs-registry — no crypto, no Enclave, runs in CI
  EncryptedFieldCoverageTests.swift  existing; derives its fixture from rotatedFields
```

**Declarations belong on the models**, next to the properties they name. A list anywhere else can
drift from what it describes, which rebuilds the problem one level up.

**The registry and the walk do not belong in `Manager.Security`.** That file already holds
activation, deactivation, PIN verification, lockout, blob slots and the migration, and is where
Bugs 46, 57, 63, 68, 69, 75, 76, 78 and 79 live. Putting the mechanism that prevents rotation bugs
inside the file that generates them is the wrong ownership: `Manager.Security` decides *when* to
rotate; *what* gets rotated is a property of the data model. That blurring is why
`VaultEntry.visibleThroughDepth` is hand-rotated at two sites inside `Manager+Security` today.

`Manager.Security` keeps one line per path: *at this step, rotate everything.*

---

## Phasing

| Phase | Scope | Cost | Verified by |
|---|---|---|---|
| **1** | `RotationRegistryTests` — schema-vs-registry, against the *existing* hand-written rotation. Registry is initially a literal list | S | Runs in CI, no Enclave. Catches Bugs 75/76's class immediately, before any refactor |
| **2** | Explicit two-key signature through `reencryptAllFields` / `reencryptKeyRecords` | S–M | Existing rotation tests; the SE-derivation count should drop sharply |
| **3** | `rotatedFields` + `RotationPolicy` per type; `reencryptAllFields` iterates it; tripwire derives from it | M | Existing tripwire and behavioural tests, now auto-extending |
| **4** | `rotateAll` walk; value passes pulled out of both paths | M | Both paths' existing tests; the two halves become diffable |
| **5** | Extend to the remaining types — the six rotated with no tripwire, `VaultEntry` first | S–M | Tripwire |

**Phase 1 is worth doing on its own** even if nothing else follows. It is cheap, needs no Enclave,
and guards the two most expensive bugs in the tracker. It also stress-tests the `notRotated` list
before any refactor depends on it — expect at least one schema type to be harder to classify than
the contract's table suggests.

## What proves it

- **Schema-vs-registry** — pure structure. No crypto, no Enclave, runs on CI runners. This is the
  one that would have caught Bugs 75 and 76.
- **Round-trip, driven by `rotatedFields`** — populate every entry with a distinct marker, rotate,
  assert each reads back. Because the fixture derives from the production list, adding a field
  extends the test automatically. This is what converts awareness into coverage.
- **Fault injection already exists.** `TestKeyManager.simulatesHybridKeyUnavailable`, added for
  Bug 78, forces key derivation to return nil — precisely the unreadable condition. So the failure
  path is drivable deterministically **without an Enclave**, meaning these tests need not join the
  260 gated ones.
- Test against the **real** `activateSecureMode` / `deactivateSecureMode`, per the contract's own
  rule: *"The helper is rarely the bug; the missing call is. A unit test of `reKeyOrPurgeAll` passed
  throughout the entire lifetime of the deactivation bug."*

## Open decisions

1. **Does `notRotated` need a reason string, or is membership enough?** A reason costs nothing and
   is the only place the "why" survives; the contract's second table shows the reasons are
   non-obvious and load-bearing.
2. **Should `Contact.Message` be classified?** The contract notes it is *"registered in the schema
   but has no local encryption helpers — verify before assuming, if it is ever used."* Phase 1
   forces the question.
3. **Does the registry walk own `modelContext.save()` ordering**, or does each caller? The "missing
   save" failure mode (contract §158) is a real regression class and the answer determines whether
   `rotateAll` can be a pure function.

## What this does not solve

- **C1's security-decision sites.** Making rotation coverage structural makes stranded fields
  *exceptional* rather than a standing condition, which shrinks C1 — but the ~25 sites where a
  decrypt failure silently becomes a security default are a separate fix.
- **Existing stranded data.** Nothing here recovers a value already sealed under a deleted key.
  Bugs 77 and 80's damage remains unrecoverable.
- **The forensic-quiet property.** The system will still degrade silently at runtime, deliberately.
  This moves detection to build time, which is the only place it can be loud.
