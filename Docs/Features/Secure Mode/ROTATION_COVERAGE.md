# Rotation Coverage — making the Model Coverage contract executable

**Status:** Scoping. No code written. Proposed 2026-08-16, **revised the same day** after a
scoping review found the first version conflated detection with prevention and absorbed an
unrelated fix. See "What the first version got wrong".
**Owner doc it extends:** [`SecureMode+RotationContract.md`](../../../Occulta/Features/SecureMode/SecureMode+RotationContract.md),
"Model Coverage" — this does not replace that reasoning, it proposes making it enforceable.
**Register item:** supersedes F3 in `Docs/Audit/OPEN_LIMITATIONS.md`.

**Note on placement:** this file lives under `Docs/` deliberately. Anything under `Occulta/` is
inside an Xcode 16 file-system-synchronized root group and ships in the app bundle unless added to
`membershipExceptions` — see §6 of `Docs/Audit/SECURITY_CHECKLIST.md`, where sixteen internal
documents were found in a Release archive.

---

## Goals

| | Goal | Driven by |
|---|---|---|
| **G1** | A new **field** on a covered model cannot be silently missed by rotation | Bug 77 |
| **G2** | A new **model** cannot be silently missed entirely | Bugs 75, 76 |
| **G3** | A model cannot be in one rotation path but not the other | `Message.Draft`, 2026-08-14 |
| **G4** | Detection happens at **build/test time** | Runtime degrades silently *by design*; by the time it is observable the superseded key is deleted and the value is unrecoverable |
| **G5** | The forensic-quiet runtime behaviour is not regressed | Stated invariant, not an accident |

**G4 is the one that sets the bar, and it asks for *detection*, not prevention.** The harm is
shipped, unrecoverable data loss. A defect caught in CI never ships, so catching is sufficient.
Making a wrong state unrepresentable is strictly better but is a *maintainability* argument, and it
is scoped separately below rather than assumed.

### Explicit non-goals

Two improvements surfaced while scoping this. Both are real and neither serves G1–G3, so they are
**not** part of this work:

- **G6 — remove Secure Enclave derivations from rotation.** Performance and reliability; feeds C2.
- **G7 — make the "rotate before commit" ordering type-enforced.** A live data-loss footgun.

Both are delivered by the same change, scoped as its own item under "Separate: explicit
decrypting and encrypting keys". It is probably higher value than anything in G1–G3, which is
exactly why it should be justified on its own merits and not smuggled into a safety refactor.

---

## The problem

Key rotation stages a new local DB key, re-encrypts, commits, then deletes the superseded key.
Anything not re-encrypted in between is sealed under a key that no longer exists — permanently,
because the hybrid key needs a Secure Enclave half that is non-exportable.

Three levels must agree with reality, and each has failed:

| Level | Failure |
|---|---|
| Type | Bugs **75**, **76** — `Group` and `AppLayerConfig` missing from both paths |
| Field | Bug **77** — `maxBundleVersion`, `deletionToken` missing from `reencryptAllFields` |
| Path | `Message.Draft` correct in activation from the start, absent from deactivation until 2026-08-14 |

Every instance failed **silently**, and the contract is right that this is by design rather than
bad luck: `reencryptAllFields` nils fields it cannot decrypt, read accessors have safe fallbacks,
`if let` swallows a missing key. That quiet degradation is correct for forensic reasons (G5) and is
exactly what hides this bug class.

### There are four lists, not two

Adding one encrypted field to `Contact.Profile` today requires editing **four** places:

| # | List | Where |
|---|---|---|
| 1 | Tripwire name list | `EncryptedFieldCoverageTests` |
| 2 | `populateEncryptedFields` — hand-assigned, one line per field (`:297`) | test |
| 3 | The 22 `#expect` assertions (`:175-204`) | test |
| 4 | `reencryptAllFields` hand-assignments | **production** |

**Only #1 is enforced.** The tripwire tells you a property is new; nothing forces 2, 3 or 4.

### Why the tripwire alone is not enough

It is well-built and its header is honest: *"This cannot tell whether a new field needs re-keying;
it forces the decision to be made."* The gap is how it is silenced — its guidance ends *"Then add
the name to the list in this test."* Adding a name to a **test-only name list** is the same act
that quiets the alarm, so it proves *awareness*, not *coverage*.

**Direct evidence that prose enforcement does not hold.** The contract's enforcement table stated
`Message.Draft` had *"no name tripwire"*, and its "Adding a new model" steps told the reader to add
one — after commit `8a431ac` had. Both corrected 2026-08-16. The document tracking which models are
enforced had drifted from the models: the same failure mode, one level up.

### What blocks full automation

`Mirror` on a SwiftData `@Model` enumerates every stored property but **erases every type to
`_SwiftDataNoType`** (`EncryptedFieldCoverageTests.swift:23-26`). You cannot ask "is this a `Data?`",
and `Mirror` cannot write. So encrypted fields can be neither auto-discovered nor auto-populated,
and name-keyed lists with explicit accessors are forced.

The goal is therefore not to remove the lists. It is to have **one** per model, and to make the act
of extending it also the act of proving coverage.

---

## Design

### G1 — collapse lists 1–3 into one probe table (test-side)

```swift
extension Contact.Profile {
    static let fieldProbes: [String: FieldProbe<Contact.Profile>] = [
        "givenName":        .string(\.givenName, "given"),
        "maxBundleVersion": .data(\.maxBundleVersion, Data([0x07])),
        "deletionToken":    .preserving(\.deletionToken, Data([1])),
        …
    ]
    static let plaintextFields: Set<String> = ["encryptionScheme", …]
}
```

One table drives all three existing uses: the tripwire asserts
`fieldProbes.keys ∪ plaintextFields == Mirror` names; the behavioural test populates from it and
reads back from it.

**You cannot add a name without supplying a keypath and a probe value.** And if
`reencryptAllFields` (list 4) misses the field, the read assertion fails. G1 achieved, **test-only,
no production change** — the keypaths live in a test extension.

`.preserving` marks fields whose *presence* carries meaning independently of content, so the
unreadable-stays-non-nil case is asserted rather than assumed. `deletionToken` is the motivating
case: nil there means "not deleted", so clearing it un-deletes contacts.

### G2 — type registry checked against the schema

```swift
static let rotatableModels: [String] = [ … ]
static let notRotated: [String: String] = [    // type → the key that seals it instead
    "VaultEntry":   "content under the vault key; only visibleThroughDepth is local-DB",
    "CustodyShard": "deriveShardCustodyKey — automatic shard ops run without user approval",
    …
]
```

A test asserts every type in the app's `Schema([...])` literal appears in exactly one. **The schema
is the anchor that makes this structural** — it is not a fixture, it is the array the app
`fatalError`s without, so it cannot be quietly forgotten.

**Prerequisite, and the one production change here:** `Schema` is currently a **local inside
`OccultaApp.init()`** and unreachable from tests. It must be extracted to a `static let` first.

The contract's second Model Coverage table is the seed for `notRotated`, including its warning that
adding one of those to the rotation *"is as much a bug as leaving one of the above out"*.

### G3 — one round-trip across every model, through both real paths

Populate every model, run the **real** `activateSecureMode`, assert everything reads; then the real
`deactivateSecureMode`, assert everything reads. A model missing from either path fails.

Per the contract's own rule: *"The helper is rarely the bug; the missing call is. A unit test of
`reKeyOrPurgeAll` passed throughout the entire lifetime of the deactivation bug."*

This needs no refactor. It is a test, and it is the direct check for G3.

---

## Separate: explicit decrypting and encrypting keys

**Serves G6 and G7, not G1–G3. Justified on its own merits; can land before or after the above.**

`reencrypt(string:to:aad:)` (`Contact+Model+Reencrypt.swift:128`) takes the encrypting key as a
parameter but decrypts through `ciphertext.decrypt()` — the **ambient** extension, which builds
`Manager.Crypto()` and derives whatever the canonical key currently is.

Encrypting key explicit; **decrypting key implicit and global.**

That is why *"must run before `commitStagedLocalDBKey()`"* exists, and it is enforced only by a
comment. If the commit ran first, `.decrypt()` would silently switch to the new key, every field
would fail, and `reencrypt(data:)` returns `nil` on failure — mass silent data loss, reachable by
reordering two lines. Bug 78's shape.

```swift
func rotateAll(decryptingKey: SymmetricKey,
               encryptingKey: SymmetricKey,
               aad: Data) throws
```

- **The ordering constraint becomes type-enforced** rather than comment-enforced (G7).
- **It removes N×fields SE derivations.** Each ambient `.decrypt()` re-derives the hybrid key — SE
  retrieval, ECDH, keychain read, HKDF. Rotation is the hottest path in the app and this is the
  cost profile behind Bug 74's `0x8BADF00D` watchdog kill (G6, feeds C2).
- **The group-after-drafts ordering dissolves**, since it exists only because `Group.readID()`
  decrypts with the ambient key.

`Group.reencrypt(from:to:)` and `AppLayerConfig.reencrypt(from:to:)` — both added later, as the
Bug 75/76 fixes — already take two keys. `Contact.Profile` is the odd one out; the newer code
already reached this conclusion.

### What must not move into a shared walk

Two genuine asymmetries, and neither is re-encryption:

- **Deactivation rewrites values.** `Manager+Security.swift:877-887` seals *computed*
  `visibleThroughDepth`, `globalTrusteeDepth`, `originDepth`. Restore logic that happens to need
  encryption; activation re-encrypts existing values instead.
- **The vault-entry nil policy is opposite in each direction.** Activation (`:574`) turns nil into
  sealed `hiddenData` — *"no silent skips"*. Deactivation (`:917`) skips nil. Both deliberate.

Today these are interleaved with re-encryption in one loop, which is why the two paths look
different enough that a missing model went unnoticed. Split them and the rotation halves become
diffable; the value passes run after, under `encryptingKey`.

---

## Optional: production `rotatedFields` (prevention, not detection)

Collapsing list 4 into the same table — `reencryptAllFields` iterating a production dictionary
rather than hand-assigning — makes a missed field **unrepresentable** rather than merely caught,
and reduces adding a field from four edits to one.

**Deliberately deferred.** G4 asks for detection, and the steps above deliver it. Revisit once they
are in and the four-lists-to-one saving can be judged against the cost of touching rotation code.

---

## Sequence

| # | Step | Serves | Cost | Risk to rotation |
|---|---|---|---|---|
| 1 | Extract `Schema` to a static; schema-vs-registry test | **G2** | S | None |
| 2 | Probe table replacing lists 1–3 | **G1** | S–M | None — test-side |
| 3 | All-models round-trip through both real paths | **G3** | M | None |
| 4 | Explicit two-key signature | G6, G7 | S–M | Real; own item |
| 5 | Production `rotatedFields` | maintainability | M | Real; deferred |

**Steps 1–3 close the entire stated goal**, are all test-side but for one extraction, and would
have caught every bug in the table above. Step 1 alone is worth doing immediately: no crypto, no
Enclave, runs on CI runners, guards the two most expensive bugs in the tracker.

Step 1 also stress-tests the `notRotated` classification before anything depends on it — expect at
least one schema type to be harder to classify than the contract's table suggests.

## What proves it

- **Schema-vs-registry** — pure structure, no crypto, no Enclave, runs in CI. Catches Bugs 75/76.
- **Probe-table round-trip** — because the fixture *is* the list, adding a field extends the test
  automatically. This is what converts awareness into coverage.
- **Fault injection already exists.** `TestKeyManager.simulatesHybridKeyUnavailable`, added for
  Bug 78, forces key derivation to return nil — precisely the unreadable condition. The failure
  path is drivable **without an Enclave**, so these need not join the 260 gated tests.

## Open decisions

1. **Does `notRotated` need a reason string?** It costs nothing and is the only place the "why"
   survives; the contract's second table shows the reasons are non-obvious and load-bearing.
2. **Should `Contact.Message` be classified?** The contract notes it is *"registered in the schema
   but has no local encryption helpers — verify before assuming."* Step 1 forces the question.
3. **Who owns `modelContext.save()` ordering** if step 4 lands — the walk or each caller? The
   "missing save" failure mode (contract §158) is a real regression class.

## What this does not solve

- **C1's security-decision sites.** Making coverage structural makes stranded fields *exceptional*
  rather than standing, which shrinks C1 — but the ~25 sites where a decrypt failure silently
  becomes a security default are a separate fix.
- **Existing stranded data.** Nothing here recovers a value sealed under a deleted key. Bugs 77 and
  80's damage remains unrecoverable.
- **The forensic-quiet property.** The system still degrades silently at runtime, deliberately
  (G5). This moves detection to build time, the only place it can be loud.

---

## What the first version got wrong

Recorded because the errors are the kind that recur.

- **It conflated detection with prevention.** It proposed a production refactor (list 4) as though
  required, when G4 asks only for build-time detection and a test-side table delivers that.
- **It absorbed an unrelated fix.** The two-key change serves G6/G7, not the coverage goals. Bundled
  in, it made the work look like one large change that must land together — and put the riskiest
  edit, inside rotation, on the critical path of a safety improvement.
- **It undercounted the lists as three.** There are four; `populateEncryptedFields` and the
  assertion block are separately hand-maintained.
- **It claimed step 1 needed no production change.** `Schema` is a local inside `OccultaApp.init()`
  and must be extracted first.
