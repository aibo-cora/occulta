# LayerStore — Design & Declarations

`Manager.Security.LayerStore` is the cryptographic container for the plausible-deniability
layer stack. It owns all file I/O and AES-GCM operations for storing and restoring sensitive
contact data across activation and deactivation cycles.

See `plan.md` Step 4 for the full activation and deactivation sequences that drive this store.

---

## Two roles

**1. Forensic deniability.** The store file exists on every Occulta install from the first
launch onward — before Secure Mode is ever configured. A forensic examiner cannot correlate
its creation or modification timestamp with Secure Mode activation. The file is indistinguishable
from a vault backup: UUID filename, `.occbak` extension, no header, no magic bytes, no version
field. It is rewritten on every `ModelContext` save (debounced 30 s) and unconditionally every
24 hours so its Last-Modified timestamp tracks normal app activity.

**2. Cryptographic container.** When Secure Mode is activated, `push` replaces the no-op file
with a real payload: the full decrypted contact data (including ML-KEM material) for every
sensitive contact at that depth. `pop` during deactivation reads that payload and provides the
plaintext that `Manager.Security` re-encrypts under the new DB key. The store itself has no
knowledge of the DB key, key rotation, or SwiftData — it only handles raw ciphertext I/O and
AES-GCM.

---

## Declarations

### Payload types

```swift
/// One sensitive contact serialised for a deniability layer.
/// Fields are decrypted plaintext — the activation sequence decrypts them
/// from the DB before constructing this record. The restore path re-encrypts
/// under the new DB key during deactivation.
struct LayerContact: Codable {
    let draft: Contact.Draft          // full contact data including ML-KEM material
    let signedAttributes: Data?       // decrypted JSON-encoded [SignedAttribute]; nil if never a trustee
    let visibleThroughDepth: Int?     // restored verbatim on deactivation (Bug 23)
}

/// The complete payload for one activation layer.
struct LayerPayload: Codable {
    let sequenceNumber: Int           // strictly increasing per push; corruption detection on pop
    let slotIndex: Int                // which of the 32 slots; consistency check on pop
    let contacts: [LayerContact]
}
```

**What is NOT stored:**
- Vault per-entry keys (PEKs) — the vault key derives from a dedicated SE key independent of
  DB key rotation; PEKs never need re-wrapping. Storing them would widen the attack surface
  since a store compromise requires only the SE Secure Mode key, bypassing the biometric gate
  that otherwise protects vault content (Bug 8).
- Prekeys — locked in-place alongside contact rows in SwiftData.
- `CustodyShard` records — their accessibility in duress mode is a deferred decision.

### I/O backend

```swift
/// Raw ciphertext I/O. No crypto knowledge — all AES-GCM lives in LayerStore.
/// Abstracted for testability; production uses AppGroupLayerStoreBackend.
protocol LayerStoreBackend {
    func write(_ data: Data) throws
    func read() throws -> Data
    func delete()
    var exists: Bool { get }
}

/// Production backend — reads and writes a single .occbak file in the Secure Mode
/// blobs directory inside the shared app group container.
/// File attributes on every write: .completeFileProtection + isExcludedFromBackup = true.
struct AppGroupLayerStoreBackend: LayerStoreBackend { }

/// In-memory backend for unit tests only. Not thread-safe.
final class InMemoryLayerStoreBackend: LayerStoreBackend { }
```

### Manager.Security.LayerStore

```swift
extension Manager {
    @Observable final class Security {

        final class LayerStore {

            // MARK: - Errors

            enum Error: Swift.Error {
                case notFound
                case encryptionFailed
                case decryptionFailed
                case sequenceNumberMismatch(expected: Int, got: Int)
                case slotIndexMismatch(expected: Int, got: Int)
                /// Thrown from push() before any I/O — no side effects.
                case payloadTooLarge(contacts: Int, encodedBytes: Int, limit: Int)
            }

            // MARK: - Constants

            /// Number of fixed slots in the store file.
            /// Must equal AppLayerConfig.maxVerifierCount so neither the file size
            /// nor the verifier array length leaks more information than the other.
            static let slotCount: Int = 32

            /// Fixed plaintext size per slot. All slots — real and padding — are sealed
            /// to exactly this length so every slot ciphertext is identical in size.
            /// 32 KB accommodates ~30 contacts with full ML-KEM material per layer.
            static let slotPlaintextSize: Int = 32 * 1024

            /// Ciphertext size per slot: nonce(12) + ciphertext(slotPlaintextSize) + tag(16).
            static var slotCiphertextSize: Int { slotPlaintextSize + 28 }

            // MARK: - Init

            init(backend: any LayerStoreBackend = AppGroupLayerStoreBackend())

            // MARK: - Activation / deactivation

            /// Writes payload into slotIndex; re-seals all other slots with fresh nonces.
            /// Encodes payload first and throws .payloadTooLarge before any I/O if it
            /// exceeds slotPlaintextSize.
            func push(_ payload: LayerPayload, key: SymmetricKey, slotIndex: Int) throws

            /// Decrypts slotIndex, validates sequenceNumber and slotIndex fields,
            /// replaces that slot with random bytes, re-seals all remaining slots
            /// with fresh nonces, writes full file, returns payload.
            func pop(key: SymmetricKey, slotIndex: Int, expectedSequenceNumber: Int) throws -> LayerPayload

            // MARK: - Slot assignment

            /// Returns a cryptographically random slot index not in `excluded`.
            func randomSlot(excluding excluded: Set<Int> = []) -> Int

            // MARK: - No-op maintenance

            /// Creates the store file on first launch; rewrites if older than 24 hours.
            /// Called from OccultaApp.init() behind the secureMode feature flag.
            func maintain()

            /// Unconditional rewrite with fresh random slots.
            /// Call after deactivation. Never call when Secure Mode is active —
            /// it would destroy the real payload.
            func rewrite()

            // MARK: - Key derivation

            /// HKDF-SHA256(IKM: seKey, info: "layer-store-key", outputLen: 32).
            /// Domain-separated from PIN verifier keys.
            func deriveKey(from seKey: SymmetricKey) -> SymmetricKey?

            // MARK: - Capacity estimation

            /// Upper-bound estimate of the serialised LayerContact size for a profile,
            /// computed from raw encrypted field sizes — no decryption required.
            /// Overestimates by ~28 bytes per field (AES-GCM overhead); safe for
            /// capacity checks in the contact classification UI.
            func estimatedSize(for profile: Contact.Profile) -> Int
        }
    }
}
```

---

## Wire format

The store file is always exactly `slotCount × slotCiphertextSize` bytes. Every slot is
AES-GCM sealed to `slotPlaintextSize` bytes of plaintext regardless of whether it holds a
real payload or random padding. An examiner always sees 32 identical-looking ciphertexts.

```
slot 0  │ AES-GCM(slotPlaintextSize bytes — random or LayerPayload JSON + zero-pad)
slot 1  │ AES-GCM(...)
...
slot k  │ AES-GCM(LayerPayload JSON + zero-pad)   ← real slot; index unknown to examiner
...
slot 31 │ AES-GCM(...)
```

No header. No magic bytes. No version field. No slot count.

---

## Slot assignment

Each activation chooses a slot index at random. The index is stored encrypted in
`AppLayerConfig.sealedBlobSlots` (one encrypted `Int` per depth, padded to `slotCount`
entries with random same-size values).

| Layer | Pool | Notes |
|---|---|---|
| Real (depth 0) | All 32 slots | Chosen once at first activation; never reassigned |
| First duress (#1) | 31 slots (real excluded) | Preserved permanently; never overwritten |
| Duress #2, #3, … | 31 slots (real excluded) | Expendable; may collide with each other |

The real slot is permanently excluded from every duress write. The first duress slot is
excluded from the #2 write pool so the two most important payloads (real contacts and the
convincing decoy) are always distinct.

### Why 32 slots

32 slots provides probabilistic cover for the real slot's permanent exclusion. The probability
that any specific slot is skipped N consecutive activations purely by chance:

| N activations | P(skipped, 32 slots) | P(skipped, 8 slots) |
|---|---|---|
| 1 | 96.8% | 87.5% |
| 3 | 90.3% | 66.9% |
| 5 | 83.9% | 51.3% |

At 32 slots a forensic examiner has no statistical basis to flag the permanently-excluded real
slot through realistic coercion depth (1–3 activations). At 8 slots the omission is visible
by 5 activations.

---

## Full regeneration on every write

Every `push` and `pop` re-seals **all 32 slots** with fresh AES-GCM nonces — real payloads
and padding alike. The algorithm:

```
for each slot i in 0..<slotCount:
    attempt AES.GCM.open(slots[i], using: key)
    success  → re-seal the decrypted plaintext with a fresh nonce   (real payload at another depth)
    failure  → seal fresh random bytes                               (padding; tag mismatch expected)
```

The target slot (push: destination; pop: source) is handled separately before this loop.
On `push` it receives the new payload. On `pop` it receives fresh random bytes (erased).

Without full regeneration a forensic examiner can diff two snapshots and identify static
ciphertexts — padding slots that never change reveal which slots hold real payloads, and
the permanently-protected real and first-duress slots would be trivially identifiable.

---

## Sequence numbers

Each `LayerPayload` carries a `sequenceNumber: Int` that is strictly increasing per push.
`pop` validates `payload.sequenceNumber == expectedSequenceNumber` (stored encrypted in
`AppLayerConfig`) before returning. A lower-than-expected sequence number indicates the
decrypted payload is from an older interrupted activation cycle; deactivation aborts rather
than restoring stale contact data.

---

## Deactivation chain

Regardless of current depth, deactivation always follows a two-step chain:

1. Any expendable duress layer → first duress layer (#1)
2. First duress layer (#1) → depth 0 (Secure Mode off, `rewrite()` called)

The convincing duress view is always the last stop before the app returns to normal. A
coercer deactivating from any depth always passes through the first-duress contacts —
never a direct return to the real app.

---

## Cryptography

```
layerKey = HKDF-SHA256(IKM: seKey, info: "layer-store-key", outputLen: 32)
slot     = AES-GCM(layerKey, plaintext, randomNonce)   [combined: nonce ∥ ciphertext ∥ tag]
```

SE binding prevents all off-device attacks — the key is inaccessible without the device
and biometrics/passcode. No PBKDF2: on-device code execution defeats any KDF regardless of
iteration count, and PBKDF2 added ~1 s of main-thread blocking for no real gain.

All 32 slots use the same `layerKey`. This is what enables full regeneration in `push`/`pop`
— the store can attempt decryption of every slot and distinguish real payloads (authentication
succeeds) from padding (authentication fails, tag mismatch).

---

## No-op maintenance

The store file is created on first app launch, before Secure Mode is ever configured.
`maintain()` is called from `OccultaApp.init()`. `rewrite()` is triggered on every
`ModelContext.didSave` notification (debounced 30 s), gated on `!security.isSecureModeActive`.

The no-op file writes `slotCount` slots of AES-GCM sealed random bytes — indistinguishable
from a file with real payloads. When Secure Mode is later activated, `push` replaces one of
those slots with the real payload; the remaining 31 continue to be random bytes.

---

## Capacity estimation

`estimatedSize(for:)` sums the raw encrypted `Data` field sizes on `Contact.Profile` without
decrypting. This overestimates the true serialised size by ~28 bytes per field (AES-GCM nonce
+ tag overhead) — a safe upper bound. The contact classification step (step 3 of
`SecureModeSetupFlow`) uses this to maintain a live capacity indicator: pre-compute sizes
for all contacts on appear (O(n), no crypto), then update a running total on each toggle (O(1)).

`push` independently enforces the hard limit: it encodes the payload first and throws
`.payloadTooLarge` before touching the store if `encoded.count > slotPlaintextSize`.

---

## AppLayerConfig additions

```swift
/// Encrypted slot index per depth, parallel to sealedDuressVerifiers.
/// Index 0 = real layer slot (depth 0). Index N = duress layer N slot.
/// Padded to slotCount entries with random same-size values so the array
/// length does not reveal how many real layers are active.
var sealedBlobSlots: [Data]

/// Strictly increasing counter written at each push; read back to validate
/// on pop. One value per depth, parallel to sealedBlobSlots.
var layerSequenceNumbers: [Data]
```
