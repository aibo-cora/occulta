# Bundle Wire Format v4 — Specification

**Status:** Ready for implementation  
**Replaces:** `v3fs` JSON serialisation throughout the encryption pipeline  
**Related:** `Docs/Features/Crypto/bundle.md` (protocol overview), `Docs/Features/Rust Package/RUST_PACKAGES_SPEC.md`

---

## 1. Problem

Encrypting a 200 MB attachment (e.g. a video) currently produces a `.occ` file of ~474 MB — a 2.37× size increase. This is not inherent cryptographic overhead. AES-256-GCM adds exactly 28 bytes (12-byte nonce + 16-byte tag). The inflation comes entirely from serialisation.

### Root Cause

`OccultaBundle` and its nested types are `Codable` structs serialised via `JSONEncoder`. `Data` fields have no native JSON representation, so Foundation encodes every `Data` value as a base64 string (4/3 the size of the raw bytes). The encryption pipeline nests `Data`-in-`Codable` at three independent layers, and each layer is unaware that its input already contains binary-encoded content:

| Layer | Call site | What inflates |
|---|---|---|
| 1 — Basket | `ComposableMessage.swift:521` `JSONEncoder().encode(basket)` | `File.content: Data?` → base64 |
| 2 — SealedPayload | `Contact+Manager.swift:955` `JSONEncoder().encode(sealedPayload)` | `SealedPayload.message: Data` → base64 |
| 3 — OccultaBundle | `OccultaBundle.swift:397` `JSONEncoder().encode(self)` | `OccultaBundle.ciphertext: Data` → base64 |

Net factor: (4/3)³ ≈ 2.37×. For a 200 MB file: 200 MB → ~267 MB (layer 1) → ~356 MB (layer 2) → ~474 MB (layer 3).

---

## 2. Solution Overview

Replace all three `JSONEncoder` calls on large `Data` fields with a **binary wire format** that carries raw bytes directly. The result:

- 200 MB file → ~200 MB `.occ` + ~1 KB overhead (metadata headers)
- AES-GCM's inherent 28-byte overhead is the only non-content addition

The binary format is implemented in a new `WireHandle` struct. The existing `OccultaBundle` struct remains the in-memory representation used throughout `ContactManager` and `Manager.Crypto` — `WireHandle` is purely a codec layer.

`WireHandle` is designed so that when the Rust package (`occulta-protocol`) is implemented, each method body becomes a single FFI call. The binary layout documented here is the Rust module's API contract.

---

## 3. Versioning

### 3.1 New version: v4

The binary format is a wire-breaking change and requires a new version value.

Add `.v4` to `OccultaBundle.Version`:

```swift
enum Version: String, Codable {
    case v1
    case v2
    case v3fs
    case v4        // binary wire format — this spec
    case unsupported
}
```

Update `currentVersion`:

```swift
static let currentVersion: Version = .v4
```

> **Note:** The existing comment at `OccultaBundle.swift:86–88` warns against adding `Version` cases for new features. A wire-format correction is the intended use of a version bump — the prohibition applies to routing new features through the outer version rather than inside `SealedPayload`. This change is explicitly exempt.

### 3.2 Version byte table

| `Version` case | String raw value | Binary byte | Status |
|---|---|---|---|
| `.v1` | `"v1"` | — | Legacy JSON, no forward secrecy |
| `.v2` | `"v2"` | — | Never shipped |
| `.v3fs` | `"v3fs"` | — | JSON format, current deployed |
| `.v4` | `"v4"` | `0x04` | Binary format, this spec |
| `.unsupported` | _(any unknown)_ | _(any unknown byte)_ | Reject |

### 3.3 Mode byte table

| `Mode` case | Binary byte |
|---|---|
| `.forwardSecret` | `0x01` |
| `.forwardSecretNoPQ` | `0x02` |
| `.longTermFallback` | `0x03` |
| `.longTermNoPQ` | `0x04` |
| `.unsupported` | _(any unrecognised byte)_ → reject |

---

## 4. Wire Layout

All multi-byte integers are **big-endian**. All fixed-width fields are mandatory. Optional fields use a presence byte followed by the value (or zeros if absent).

### 4.1 Outer Envelope (`OccultaBundle`)

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────────
0       4     magic: 0x4F 0x43 0x43 0x42  ("OCCB")
4       1     version: u8                  (0x04 for v4)
5       1     min_reader_version: u8       (minimum version to decode this bundle)
6       1     mode: u8                     (see §3.3)
7       2     flags: u16                   (reserved — write 0x0000, ignore on read)
9       1     has_prekey_id: u8            (0x00 = absent, 0x01 = present)
10      36    prekey_id: bytes             (UTF-8 UUID string, 36 bytes; zeros if absent)
46      65    ephemeral_key: bytes         (x963 uncompressed P-256, 65 bytes; zeros on longTerm paths)
111     16    fingerprint_nonce: bytes
127     32    sender_fingerprint: bytes    (SHA-256(senderPub ∥ nonce))
159     8     ciphertext_length: u64
167     N     ciphertext: bytes            (AES-GCM combined: nonce(12) ∥ ct(N-28) ∥ tag(16))
167+N   …     TLV sections (optional, see §4.4)
```

Total fixed header: 167 bytes.

### 4.2 Inner Payload (`SealedPayload`)

This is the plaintext that is passed directly to `AES.GCM.seal`. It contains two sections: a metadata JSON block and the raw message bytes.

```
Offset  Size  Field
──────  ────  ──────────────────────────────────────────────────────────
0       4     metadata_length: u32
4       N     metadata_json: UTF-8 JSON object (see §4.2.1)
4+N     8     message_length: u64
12+N    M     message: raw binary Basket bytes (see §4.3)
```

#### 4.2.1 `metadata_json` schema

All fields are optional. Absent fields are omitted (not null). Receivers treat unknown fields as no-ops.

```json
{
  "appVersion":         "1.9.0",
  "prekeyBatch":        { "generatedAt": 1234567890.0, "prekeys": [...] },
  "identityChallenge":  { ... },
  "shardOperations":    [ ... ],
  "custodyManifest":    [ "uuid-string", ... ],
  "expectedShards":     [ "uuid-string", ... ]
}
```

`appVersion` is the sender's current app version string (e.g. `"1.9.0"`). Receivers use this to update the contact's stored `maxBundleVersion`. See §6.

### 4.3 Basket

This is what `SealedPayload.message` contains. It encodes a `Basket` struct as a length-prefixed sequence of files, each split into metadata (JSON) and raw content bytes.

```
Offset  Size  Field
──────  ────  ──────────────────────────────────────────────────────────
0       4     file_count: u32

For each file:
  0     4     metadata_length: u32
  4     N     metadata_json: UTF-8 JSON object (see §4.3.1)
  4+N   8     content_length: u64             (0 if File.content is nil)
  12+N  M     content: raw bytes              (omitted if content_length == 0)
```

#### 4.3.1 File `metadata_json` schema

```json
{
  "id":     "uuid-string",
  "format": "text" | { "file": { "name": "...", "extension": "...", "note": "..." } } | "contacts" | "link",
  "date":   1234567890.0
}
```

`content` bytes carry the raw file data (video bytes, image bytes, UTF-8 text, etc.) with no encoding.

### 4.4 TLV Extension Sections

Optional sections appended after the ciphertext. Parsers that do not recognise a section type **must** skip it using `section_length`. Parsers **must not** reject a bundle solely because it contains unknown section types.

```
Offset  Size  Field
──────  ────  ──────────────────────────────────────────────────────────
0       1     section_type: u8
1       4     section_length: u32
5       N     section_bytes
```

#### Defined section types

| `section_type` | Meaning | Format |
|---|---|---|
| `0x01` | GroupEnvelope | JSON-encoded `GroupEnvelope` (see `Docs/Features/Group Messaging/SPEC.md`) |

Duplicate sections of the same type are a protocol error — parsers must throw `BundleError.malformedBundle` on the second occurrence. Unknown types are silently skipped.

---

## 5. Additional Authenticated Data (AAD)

The AAD computation is unchanged from v3fs. Both sender and receiver compute:

```
AAD = "v4".data(using: .utf8)! + JSONEncoder(.sortedKeys).encode(SecrecyContext)
```

Where `SecrecyContext` is reconstructed from the parsed outer envelope fields (`mode`, `ephemeralKey`, `prekeyID`). The JSON encoding is kept for AAD even though the wire format is binary — the AAD is tiny (<200 bytes) and the `.sortedKeys` guarantee makes it deterministic across all platforms without additional implementation work.

Any modification to `version`, `mode`, `ephemeralKey`, or `prekeyID` in the outer envelope causes `AES.GCM.open` to throw. The `fingerprintNonce` and `senderFingerprint` fields are intentionally excluded from AAD — tampering with them makes the bundle unroutable but cannot break the ciphertext.

---

## 6. Per-Contact Capability Negotiation

Senders choose the wire format based on what each contact's app can handle. This eliminates the need for a staged rollout — senders never transmit a format the recipient cannot read.

### 6.1 Stored field

Add `maxBundleVersion` to `Contact.Profile`:

```swift
var maxBundleVersion: Data?   // encrypted — nil means unknown (treat as v3fs)
```

This field is encrypted with the same local AES-GCM scheme as all other contact fields. It is **never** stored or transmitted in plaintext.

The raw (decrypted) value is a single `UInt8`:
- `nil` / absent → treat as `0x03` (v3fs)
- `0x04` → contact can handle v4 binary format

### 6.2 Deriving format on send

```swift
// In encryptBundle, before encoding the SealedPayload:
let version: OccultaBundle.Version
if let encrypted = contact.maxBundleVersion,
   let raw = try? cryptoOps.decrypt(data: encrypted),
   raw.first == 0x04 {
    version = .v4
} else {
    version = .v3fs   // unknown or old contact — safe default
}
```

### 6.3 Updating on receive

After a successful `decryptSealed`, extract `appVersion` from the decoded `SealedPayload` metadata and derive the contact's maximum supported bundle version:

```swift
// In decryptSealed, after decoding the payload:
if let appVersion = decodedPayload.appVersion {
    let maxVersion = Self.bundleVersion(forAppVersion: appVersion)
    let encrypted = try cryptoOps.encrypt(data: Data([maxVersion]))
    sender.maxBundleVersion = encrypted
}
```

The version derivation table:

| App version | `maxBundleVersion` byte | `Version` case |
|---|---|---|
| < `"1.8.2"` | `0x03` | `.v3fs` |
| ≥ `"1.8.2"` | `0x04` | `.v4` |
| ≥ `"1.9.0"` | `0x05` | `.groupCapable` |
| unknown / nil | `0x03` (safe default) | `.v3fs` |

v4 ships in app version `1.8.2`. `.groupCapable` (`0x05`) signals that the contact can receive group bundles and all sends should use `sealGroup`. It is a capability signal only — it is never written as the wire `version` byte. The sender maps `.groupCapable` → `.v4` at encode time so both sides compute identical AAD.

### 6.4 Convergence

The first message to a contact with no stored version always uses v3fs. After the first successful decryption of a reply, the stored version is updated. All subsequent messages use the negotiated format. Convergence takes at most one round trip.

---

## 7. Dispatch in `OccultaBundle`

### Encoding

```swift
// OccultaBundle.swift
func encoded(version: Version) throws -> Data {
    switch version {
    case .v4:
        return try WireHandle.encode(self)
    default:
        return try JSONEncoder().encode(self)
    }
}
```

The `version` argument comes from the caller (`encryptBundle`), which resolves it from the contact's `maxBundleVersion`.

### Decoding

```swift
// OccultaBundle.swift
static func decoded(from data: Data) throws -> OccultaBundle {
    if data.prefix(WireHandle.magic.count).elementsEqual(WireHandle.magic) {
        return try WireHandle.parse(data)
    }
    return try JSONDecoder().decode(OccultaBundle.self, from: data)
}
```

v4 receivers can read both formats. v3fs receivers that encounter a binary bundle fail with `DecodingError.dataCorrupted` — acceptable since the sender only transmits binary to confirmed v4 contacts.

---

## 8. `WireHandle` API

```swift
struct WireHandle {

    static let magic: [UInt8] = [0x4F, 0x43, 0x43, 0x42]  // "OCCB"

    // MARK: - Outer envelope

    struct Bundle {
        let version: UInt8
        let minReaderVersion: UInt8
        let mode: UInt8
        let flags: UInt16           // reserved
        let prekeyID: Data?         // 36 bytes (UTF-8 UUID) or nil
        let ephemeralKey: Data      // 65 bytes, zeros on longTerm paths
        let fingerprintNonce: Data  // 16 bytes
        let senderFingerprint: Data // 32 bytes
        let ciphertext: Data        // raw AES-GCM combined
    }

    /// Parse the outer binary envelope. Does not decrypt.
    /// Use fingerprintNonce + senderFingerprint to identify the sender before calling open.
    static func parse(_ data: Data) throws -> Bundle

    /// Decrypt the ciphertext inside a parsed bundle.
    /// Computes AAD from bundle fields and calls AES.GCM.open.
    static func open(_ bundle: Bundle, using key: SymmetricKey) throws -> Data

    /// Encode an OccultaBundle as a binary outer envelope.
    static func encode(_ bundle: OccultaBundle) throws -> Data

    // MARK: - Inner payload (SealedPayload)

    /// Encode a SealedPayload to binary. This is the plaintext passed to AES.GCM.seal.
    /// Replaces: JSONEncoder().encode(sealedPayload) in Contact+Manager.swift:955
    static func encode(payload: OccultaBundle.SealedPayload) throws -> Data

    /// Decode binary SealedPayload bytes. Called on the plaintext returned by AES.GCM.open.
    /// Replaces: JSONDecoder().decode(SealedPayload.self, from:) in Contact+Manager.swift:1250
    static func decode(payload: Data) throws -> OccultaBundle.SealedPayload

    // MARK: - Basket

    /// Encode a Basket to binary. This becomes SealedPayload.message.
    /// Replaces: JSONEncoder().encode(basket) in ComposableMessage.swift:521
    static func encode(basket: Basket) throws -> Data

    /// Decode binary Basket bytes. Called on SealedPayload.message after decryption.
    /// Replaces: JSONDecoder().decode(Basket.self, from:) in the receive pipeline
    static func decode(basket: Data) throws -> Basket
}
```

When `occulta-protocol` (Rust) is implemented, each of these methods becomes a single FFI call. The call sites in `ContactManager` and `ComposableMessage` remain unchanged.

---

## 9. Call Site Changes

| File | Line | Change |
|---|---|---|
| `ComposableMessage.swift` | 521 | `JSONEncoder().encode(basket)` → `WireHandle.encode(basket:)` (v4 contacts only) |
| `Contact+Manager.swift` | 955 | `JSONEncoder().encode(sealedPayload)` → `WireHandle.encode(payload:)` (v4) |
| `Contact+Manager.swift` | 964 | `bundle.encoded()` → `bundle.encoded(version: version)` |
| `Contact+Manager.swift` | 1250 | `JSONDecoder().decode(SealedPayload.self, from:)` → `WireHandle.decode(payload:)` |
| `OccultaBundle.swift` | 79 | `currentVersion = .v3fs` → `currentVersion = .v4` |
| `OccultaBundle.swift` | 397 | `encoded()` → `encoded(version:)` with dispatch |
| `OccultaBundle.swift` | 401 | `decoded(from:)` → magic prefix dispatch |
| `OccultaBundle.swift` | 90 | Add `.v4` case to `Version` enum |
| `Contact+Manager.swift` | 1056 | `verifyConsistency` — accept `.v4` alongside `.v3fs` |
| `Contact.Profile` (model) | new | Add `var maxBundleVersion: Data?` (encrypted) |
| `OccultaBundle.SealedPayload` | new | Add `let appVersion: String?` |

---

## 10. Compatibility Contract

These rules apply to all current and future implementations of the binary format:

1. **Unknown TLV section types must be skipped**, not rejected. Read `section_length` bytes and advance.
2. **Reserved `flags` bytes must be written as `0x0000`** and ignored on read.
3. **`min_reader_version` must be checked before any other parsing.** If the reader's version is below `min_reader_version`, throw `BundleError.unsupportedVersion` immediately.
4. **Unknown mode bytes must be decoded as `.unsupported`** and rejected before key derivation.
5. **`fingerprintNonce` and `senderFingerprint` are routing-only.** They are not in the AAD. Tampered values make the bundle unroutable; they cannot compromise the ciphertext.
6. **Version numbers are monotonically increasing and never reused.** Even retired versions (v2, never shipped) retain their slot.

---

## 11. Size Impact

| Scenario | v3fs (current) | v4 (this spec) |
|---|---|---|
| 200 MB video | ~474 MB | ~200 MB + ~1 KB |
| 10 MB photo | ~23.7 MB | ~10 MB + ~1 KB |
| 1 KB text message | ~2.4 KB | ~1 KB + ~1 KB |
| Overhead (fixed) | (4/3)³ ≈ 2.37× | 167 B header + metadata JSON |

---

## 12. Rust Portability Notes

The binary layout in §4 is the authoritative spec for the Rust implementation. Additional notes for the implementer:

- All length fields and the `flags` field are **big-endian** (`u32::from_be_bytes`, `u64::from_be_bytes`)
- Fixed-width fields use fixed-size Rust arrays (`[u8; 65]`, `[u8; 32]`, etc.), not `Vec<u8>`
- `min_reader_version` and `version` sit at fixed offsets (bytes 5 and 4) — readable without parsing the rest of the header
- `has_prekey_id` / `prekey_id` pattern avoids a length prefix for a field whose size is always exactly 36 bytes when present
- The metadata JSON inside `SealedPayload` uses `serde_json` on the Rust side; the schema is forward-compatible (unknown keys are ignored by `#[serde(deny_unknown_fields)]` must **not** be set)
- `appVersion` in `metadata_json` is a plain semver string — parse with `semver` crate or simple string comparison against the threshold version
- **AAD — `prekeyID` must serialize as `null`, not be omitted.** Swift's `JSONEncoder` emits `"prekeyID":null` when the field is nil. Rust `serde` with `skip_serializing_if = "Option::is_none"` omits the key entirely, producing different AAD bytes and causing every longTerm-path `open` to fail. Do not use that attribute on `prekey_id`. Use `#[serde(default)]` on deserialize and emit `null` on serialize.
- **AAD — `ephemeralPublicKey` base64 encoding must use RFC 4648 standard alphabet with `=` padding and no newlines.** Foundation's `JSONEncoder` uses this encoding for `Data`. In the `base64` crate this is `general_purpose::STANDARD`. URL-safe or no-pad variants produce different bytes and break cross-platform AAD.
- **AAD cross-platform test vectors are mandatory.** Before shipping the Rust implementation, generate a set of `(SecrecyContext, AAD bytes)` pairs in Swift and assert byte-identical output from Rust. Cover: forwardSecret (non-empty ephemeralPublicKey, non-nil prekeyID), longTermFallback (empty ephemeralPublicKey, nil prekeyID → `null`).
- **`open` takes raw key bytes, not a typed key.** `SymmetricKey` is CryptoKit-specific. The Swift shim extracts bytes with `key.withUnsafeBytes { Data($0) }` before the FFI call. Rust signature: `fn open(bundle: &Bundle, key: &[u8; 32]) -> Result<Vec<u8>, BundleError>`.
