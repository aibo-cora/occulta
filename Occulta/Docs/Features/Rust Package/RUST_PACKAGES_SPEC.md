# Occulta Rust Package Specifications
**Date:** May 2026
**Scope:** `occulta-protocol`, `occulta-crypto`, `occulta-ffi`, SPM build script
**Source:** Existing Swift codebase — `Key+Manager.swift`, `Crypto+Manager.swift`,
`OccultaBundle.swift`, `IdentityChallenge+*`, `VAULT_SSS_GUIDE.md`, `CLAUDE.md`

---

## Dependency Graph

```
occulta-protocol                    occulta-crypto
[serde, serde_json, sha2, zeroize]  [aes-gcm, hkdf, sha2, p256,
                                     rand, zeroize, secrecy,
  Wire format — no crypto crates      subtle, argon2, thiserror]
  OccultaBundle, SecrecyContext
  SealedPayload, WirePrekey          AES-GCM, HKDF, ECDSA verify
  ForwardSecrecy, SaltInfo           Shamir SSS, Argon2id KDF
  IdentityChallenge types            key-material validation
  fingerprint(), compute_aad()
         ↑                                    ↑
         └──────────── occulta-ffi ───────────┘
                       [uniffi]
                       UniFFI bindings only
                       Produces .xcframework
                            ↑
                       iOS app (Swift)
```

Neither `occulta-protocol` nor `occulta-crypto` depends on the other.
`occulta-ffi` is the only crate that imports both.

---

## Cross-Cutting Security Invariants

These apply to all three crates. A violation in any one is a critical defect.

1. **Rust never receives a private key.** The Secure Enclave performs all
   private key operations. Rust receives the output of `SecKeyCopyKeyExchangeResult`
   with algorithm `.ecdhKeyExchangeCofactorX963SHA256` — a 32-byte X9.63-KDF
   output, not the raw ECDH x-coordinate — and operates from there. This boundary
   is absolute. Never document these bytes as "raw ECDH"; the SE applies X9.63/SHA-256
   internally.

2. **Nonces are always generated internally.** `aes_gcm_seal` generates its own
   96-bit nonce via `rand::thread_rng()`. Callers never supply a nonce.
   The output is `nonce(12) ∥ ciphertext ∥ tag(16)` — the nonce is embedded.

3. **All secret material implements `Zeroize`.** Any type holding key bytes,
   raw ECDH output, or IKM must derive both `Zeroize` **and** `ZeroizeOnDrop`.
   `ZeroizeOnDrop` alone generates `Drop` calling `self.zeroize()` — if `Zeroize`
   is not also derived, the crate will not compile. Both attributes are required.

4. **No panics cross the FFI boundary.** Every `#[uniffi::export]` function
   wraps its body in logic equivalent to `catch_unwind`. A Rust panic across
   FFI is undefined behaviour. All functions return `Result<T, OccultaError>`.

5. **AAD computation must be byte-for-byte identical to Swift output.**
   The AAD feeds directly into AES-GCM authentication. Any byte difference
   means every bundle encoded by Swift is undecryptable by Rust and vice versa.
   Validate against extracted Swift test vectors before shipping.

6. **SaltInfo strings are protocol commitments.** They are wire-format constants.
   Adding new strings is allowed. Modifying existing strings silently breaks
   all previously encrypted data across all platforms. Never modify; never
   reuse a string for a different purpose.

7. **Constant-time operations for Shamir SSS.** All GF(2^8) arithmetic uses
   lookup tables with `subtle::Choice` comparisons. No secret-dependent branches.

8. **SE availability must be verified before key operations.** Call
   `assert_secure_key_storage()` at application startup before invoking any
   HKDF or AES-GCM function. Key material derived without a Secure Enclave
   lacks hardware binding and must not be accepted.

9. **Key material is validated before use.** `validate_key_material()` in
   `occulta-crypto` rejects all-zero inputs and wrong-length inputs. Call it
   on every ECDH output before passing to HKDF.

---

## Package 1: `occulta-protocol`

### Responsibility

Wire format definition and protocol types. No cryptographic operations except
SHA-256 for fingerprint computation. Independently auditable as a protocol
specification without reading any crypto implementation.

### Cargo.toml

```toml
[package]
name    = "occulta-protocol"
version = "0.1.0"
edition = "2021"

[dependencies]
serde         = { version = "1", features = ["derive"] }
serde_json    = { version = "1" }
sha2          = "0.10"
zeroize       = { version = "1.7", features = ["derive"] }
uuid          = { version = "1", features = ["serde", "v4"] }
base64        = "0.22"
thiserror     = "1"
```

### Module Structure

```
occulta-protocol/src/
├── lib.rs                  pub use everything relevant; Base64Data lives here
├── bundle.rs               OccultaBundle, encode, decode, compute_aad, fingerprint
├── secrecy.rs              SecrecyContext, Version, Mode, ProtocolError
├── payload.rs              SealedPayload, PrekeySyncBatch, WirePrekey, ShardOperation
├── forward_secrecy.rs      ForwardSecrecy
├── quantum.rs              QuantumKeyMaterial
├── challenge.rs            IdentityChallenge types, constants, payload builder
└── salt_info.rs            All HKDF info strings — protocol constants
```

---

### `lib.rs` — `Base64Data` lives here

`Base64Data` is used across `bundle.rs`, `payload.rs`, `challenge.rs`, and `quantum.rs`.
Placing it in `lib.rs` avoids circular module imports.

```rust
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Transparent wrapper that serialises Vec<u8> as a base64 string,
/// matching Swift JSONEncoder's default Data encoding.
///
/// Use this for every field whose Swift counterpart is `Data`.
/// `serde_json` encodes bare `Vec<u8>` as an integer array — incompatible
/// with Swift's base64 encoding.
#[derive(Debug, Clone, Default, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Base64Data(pub Vec<u8>);

impl Serialize for Base64Data {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Data {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(&s)
            .map(Base64Data)
            .map_err(serde::de::Error::custom)
    }
}
```

---

### `salt_info.rs`

All strings are protocol commitments. Encoded as `&[u8]` so callers pass them
directly to HKDF without allocation.

```rust
/// Wire-level HKDF info strings. These are protocol commitments.
/// Modifying any value is a breaking change that silently corrupts all
/// previously encrypted data. Add new constants; never modify existing ones.
pub struct SaltInfo;

impl SaltInfo {
    /// Classical long-term transport. Used when no ML-KEM material is present.
    pub const TRANSPORT: &'static [u8] =
        b"Occulta-v1-transport-2025";

    /// Classical local DB encryption (v1 — identity-key-derived).
    /// Read-only after migration to HYBRID_LOCAL_DB.
    pub const LOCAL_DB: &'static [u8] =
        b"Occulta-v1-encryption-key-2025";

    /// Hybrid PQ local DB encryption (v2 — SE + random component).
    /// Domain-separated from LOCAL_DB to prevent key equivalence during migration.
    pub const HYBRID_LOCAL_DB: &'static [u8] =
        b"Occulta-v2-local-db-pq-2026";

    /// Hybrid PQ long-term transport (identity-level ECDH + ML-KEM).
    pub const HYBRID_TRANSPORT: &'static [u8] =
        b"Occulta-v2-hybrid-pq-transport-2026";

    /// Hybrid PQ forward-secret transport (ephemeral ECDH + ML-KEM).
    /// Domain-separated from HYBRID_TRANSPORT — different ECDH keys, same ML-KEM.
    pub const HYBRID_FS_TRANSPORT: &'static [u8] =
        b"Occulta-v2-hybrid-pq-fs-transport-2026";

    /// Diceware verification key. Static prefix only.
    /// Callers append sorted(nonce_a, nonce_b) at call time for per-session uniqueness.
    pub const DICEWARE_PREFIX: &'static [u8] =
        b"Occulta-v2-diceware-2026";

    /// Vault key derivation. Dedicated SE key, biometryCurrentSet protected.
    pub const VAULT: &'static [u8] =
        b"Occulta-v1-vault-2026";

    /// Shard custody key. Dedicated SE key, device-unlock-level access.
    pub const SHARD_CUSTODY: &'static [u8] =
        b"Occulta-v1-shard-custody-2026";

    /// Secure Mode PIN sentinel encryption. Dedicated SE key (`app.layer.key.occulta.v1`),
    /// device-unlock-level access. Domain-separated from all other paths.
    pub const SECURE_MODE_PIN: &'static [u8] =
        b"Occulta-v1-secure-mode-pin-2026";

    /// Recovery buffer encryption. Reuses the shard-custody SE key with a distinct
    /// info string — domain-separated from SHARD_CUSTODY so a custody blob and a
    /// reconstruct blob are never decryptable with the same derived key.
    pub const RECOVERY_BUFFER: &'static [u8] =
        b"Occulta-v1-recovery-buffer-2026";
}
```

---

### `secrecy.rs`

JSON field names must match Swift's `JSONEncoder` output exactly, including
camelCase. The `#[serde(rename_all = "camelCase")]` attribute handles most of
this, but `prekeyID` requires an explicit `rename` because Swift uses uppercase
`ID` while `rename_all = "camelCase"` would produce lowercase `Id`.

**AAD serialisation invariant:** Swift's `.sortedKeys` sorts JSON object keys
alphabetically. `serde_json` with struct serialisation uses declaration order.
`SecrecyContext` fields are declared in alphabetical order so both orders
produce identical JSON. **Do not reorder fields** — the AAD depends on this.

```rust
use serde::{Deserialize, Serialize};
use crate::ProtocolError;

/// Wire protocol version. Raw string values are stable — do not change them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Version {
    #[serde(rename = "v1")]   V1,
    #[serde(rename = "v2")]   V2,
    #[serde(rename = "v3fs")] V3Fs,
}

impl Version {
    /// UTF-8 bytes of the raw string value. Used in AAD computation.
    pub fn raw_bytes(&self) -> &'static [u8] {
        match self {
            Self::V1   => b"v1",
            Self::V2   => b"v2",
            Self::V3Fs => b"v3fs",
        }
    }
}

/// Encryption mode. Raw string values are stable.
///
/// Note: identity challenges ride `.longTermFallback` on the wire — they do
/// not use a separate mode. New behaviour must go inside `SealedPayload`
/// optional envelopes, not new `Mode` variants, to avoid breaking old builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    #[serde(rename = "forwardSecret")]    ForwardSecret,
    #[serde(rename = "longTermFallback")] LongTermFallback,
    /// Decoded from any unknown mode string. Never written.
    /// A bundle carrying `Unsupported` mode aborts before AAD computation.
    #[serde(other)]                       Unsupported,
}

/// Authenticated key-exchange metadata. Transmitted in plaintext as AAD.
///
/// ## Field order invariant
/// Fields are declared in alphabetical camelCase key order to match
/// Swift JSONEncoder's `.sortedKeys` output byte-for-byte.
/// Do not reorder: `ephemeralPublicKey` < `mode` < `prekeyID`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecrecyContext {
    /// Sender's ephemeral P-256 public key in X9.63 format (65 bytes).
    /// `.forwardSecret`: per-message throwaway key.
    /// `.longTermFallback`: empty `Data()` — never put the sender's
    /// long-term key here; the recipient already has it and leaking it
    /// in cleartext metadata is a privacy violation.
    pub ephemeral_public_key: Base64Data,   // JSON: "ephemeralPublicKey"

    /// Which key derivation path was used.
    pub mode: Mode,                          // JSON: "mode"

    /// UUID of the recipient's prekey used for this bundle.
    /// Non-nil only in `.forwardSecret` mode.
    #[serde(rename = "prekeyID")]           // explicit: avoids rename_all lowercasing "Id"
    pub prekey_id: Option<String>,           // JSON: "prekeyID"  ← capital I, capital D
}
```

---

### `bundle.rs`

```rust
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use crate::{Base64Data, secrecy::{SecrecyContext, Version}};

/// Errors from wire-format serialisation / deserialisation.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("serialisation failed: {0}")]
    Serialise(#[from] serde_json::Error),
    #[error("deserialisation failed: {0}")]
    Deserialise(serde_json::Error),
}

/// Top-level wire container. All fields are JSON-serialised.
/// `ciphertext`, `fingerprintNonce`, `senderFingerprint` are base64-encoded Data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OccultaBundle {
    pub version:            Version,
    pub secrecy:            SecrecyContext,
    pub ciphertext:         Base64Data,   // nonce(12) ∥ ciphertext ∥ tag(16)
    pub fingerprint_nonce:  Base64Data,   // 16 random bytes — routing only, not in AAD
    pub sender_fingerprint: Base64Data,   // SHA-256(senderPub ∥ fingerprintNonce)
}

impl OccultaBundle {
    /// Encode to JSON bytes. Output must be byte-equivalent to Swift's JSONEncoder.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        serde_json::to_vec(self).map_err(ProtocolError::Serialise)
    }

    /// Decode from JSON bytes.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(data).map_err(ProtocolError::Deserialise)
    }
}

/// Compute Additional Authenticated Data.
///
/// Formula: version.rawValue.utf8 ∥ JSON(SecrecyContext, sortedKeys: true)
///
/// `SecrecyContext` fields are declared alphabetically so `serde_json`'s
/// declaration-order serialisation matches Swift's `.sortedKeys` output.
/// Validate against extracted Swift test vectors before shipping.
pub fn compute_aad(
    version: &Version,
    secrecy: &SecrecyContext,
) -> Result<Vec<u8>, ProtocolError> {
    let version_bytes = version.raw_bytes();
    let secrecy_json  = serde_json::to_vec(secrecy)
        .map_err(ProtocolError::Serialise)?;

    let mut aad = Vec::with_capacity(version_bytes.len() + secrecy_json.len());
    aad.extend_from_slice(version_bytes);
    aad.extend_from_slice(&secrecy_json);
    Ok(aad)
}

/// Compute sender fingerprint.
///
/// Formula: SHA-256(senderLongTermPublicKey ∥ fingerprintNonce)
/// `senderLongTermPublicKey`: 65-byte X9.63 uncompressed P-256 public key
/// `fingerprintNonce`: 16 random bytes, unique per bundle
///
/// Output: 32 bytes. Used for pre-decryption routing only — not secret.
pub fn compute_fingerprint(
    sender_public_key: &[u8; 65],
    fingerprint_nonce: &[u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(sender_public_key);
    hasher.update(fingerprint_nonce);
    hasher.finalize().into()
}
```

---

### `payload.rs`

Fields added in v1.6–v1.7 (`shard_operations`, `custody_manifest`, `expected_shards`)
are marked `#[serde(default)]`. If Rust ever re-serialises a `SealedPayload`, all
fields must be present to avoid silently dropping data from newer Swift builds.

```rust
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::Base64Data;

/// Inner payload — encrypted content of OccultaBundle.ciphertext.
/// Never appears in plaintext on the wire.
///
/// `message` is `Base64Data` because Swift's JSONEncoder encodes `Data` as
/// a base64 string. `serde_json` would encode `Vec<u8>` as an integer array —
/// use `Base64Data` for every field whose Swift counterpart is `Data`.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SealedPayload {
    pub message:      Base64Data,
    #[serde(default)]
    pub prekey_batch: Option<PrekeySyncBatch>,
    #[serde(default)]
    pub identity_challenge: Option<IdentityChallengeEnvelope>,
    /// SSS shard-protocol operations. Added v1.6. Old builds ignore this field.
    #[serde(default)]
    pub shard_operations: Option<Vec<ShardOperation>>,
    /// IDs of all custody shards this sender holds for the recipient.
    /// Trustee → owner direction only. Added v1.7.
    #[serde(default)]
    pub custody_manifest: Option<Vec<String>>,   // UUID strings
    /// IDs the owner expects this trustee to hold. Added v1.7.
    /// Owner → trustee direction only.
    #[serde(default)]
    pub expected_shards: Option<Vec<String>>,    // UUID strings
}

/// A versioned batch of the sender's prekey public keys.
/// Encrypted inside `SealedPayload.ciphertext` — never visible to observers.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct PrekeySyncBatch {
    pub generated_at: f64,           // Unix timestamp — matches Swift Date encoding
    pub prekeys: Vec<WirePrekey>,
}

/// Single prekey on the wire. Only id + publicKey — no contactID.
/// contactID never appears on the wire (metadata leak prevention).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct WirePrekey {
    pub id:         String,          // UUID string — matches Swift String field
    pub public_key: Base64Data,      // 65-byte X9.63 P-256 public key
}

/// SSS shard-protocol operation inside SealedPayload. Added v1.6.
/// Old builds silently ignore this type.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ShardOperation {
    pub kind:         ShardOperationKind,
    pub attribute:    Option<Base64Data>,  // SignedAttribute shard payload
    pub attribute_id: Option<String>,      // UUID string — old shard to delete on .replace
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub enum ShardOperationKind {
    #[serde(rename = "distribute")] Distribute,
    #[serde(rename = "replace")]    Replace,
    #[serde(rename = "handback")]   Handback,
    #[serde(other)]                 Unsupported,
}

/// Identity-challenge sub-envelope inside SealedPayload.
///
/// ## Wire format
/// Matches `IdentityChallengeEnvelope` in Swift (`IdentityChallenge+Envelope.swift`).
/// The binary challenge or response data is carried as an opaque `payload` field —
/// NOT decomposed into nonce/timestamp/fingerprint. Those fields live inside the
/// 72-byte binary `ChallengePayload` struct serialised manually in Swift.
///
/// Challenge payload (72 bytes): nonce(32) ∥ timestamp_be(8) ∥ challengerFingerprint(32)
/// Response payload (variable):  challengeNonce(32) ∥ DER_signature(variable)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct IdentityChallengeEnvelope {
    pub kind:         ChallengeKind,
    /// Raw binary payload for this phase.
    /// Challenge → 72-byte `ChallengePayload` encoding.
    /// Response  → 32-byte nonce ∥ DER ECDSA signature.
    pub payload:      Base64Data,
    /// Optional freetext from challenger. Always nil on a response.
    #[serde(default)]
    pub context_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
pub enum ChallengeKind {
    #[serde(rename = "challenge")] Challenge,
    #[serde(rename = "response")]  Response,
}
```

---

### `forward_secrecy.rs`

Field types match the Swift `ForwardSecrecy` struct exactly, including
`Option<>` wrapping and `Base64Data` for `Data`-typed fields.

```rust
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::Base64Data;

/// Per-contact forward secrecy state. Stored encrypted in SwiftData.
/// This type is the decrypted plaintext of that record.
///
/// Matches Swift `ForwardSecrecy` in `ForwardSecrecy.swift`.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct ForwardSecrecy {
    /// Inbound prekeys received from the contact. Consumed FIFO by sender.
    /// `None` and `Some([])` are both treated as "no prekeys available".
    #[serde(default)]
    pub encoded_prekeys: Option<Vec<Base64Data>>,

    /// Timestamp of the last accepted inbound prekey batch.
    /// `None` means no batch has been accepted yet.
    /// Used to reject replayed or reordered batches.
    #[serde(default)]
    pub latest_prekeys_generated_at: Option<f64>,   // Unix timestamp, matches Swift Date?

    /// Outbound prekey batch pending delivery to the contact.
    /// Attached to every outbound message until the contact proves receipt.
    #[serde(default)]
    pub pending_outbound_batch: Option<Base64Data>,   // single Data blob, not an array
}
```

---

### `quantum.rs`

Field names match the Swift `QuantumKeyMaterial` struct (`ourCiphertext`,
`peerCiphertext`) — the Codable keys must be identical for JSON round-trips.

```rust
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ML-KEM-1024 artifacts from a PQ key exchange.
/// Stored encrypted at rest in SwiftData.
/// Shared secrets are mixed into every session key for PQ contacts.
///
/// Matches Swift `QuantumKeyMaterial` in `QuantumKeyMaterial.swift`.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct QuantumKeyMaterial {
    /// 32-byte shared secret from our ML-KEM encapsulation of the contact's key.
    pub encapsulated_secret: Vec<u8>,
    /// 32-byte shared secret from decapsulating the contact's ML-KEM ciphertext.
    pub decapsulated_secret: Vec<u8>,
    /// ML-KEM ciphertext we sent to the contact. JSON key: "ourCiphertext".
    #[serde(rename = "ourCiphertext")]
    pub our_ciphertext: Vec<u8>,
    /// ML-KEM ciphertext the contact sent to us. JSON key: "peerCiphertext".
    #[serde(rename = "peerCiphertext")]
    pub peer_ciphertext: Vec<u8>,
}

impl QuantumKeyMaterial {
    /// True if both shared secrets are exactly 32 bytes.
    /// Matches Swift's `isValid` which checks `count == 32`.
    pub fn is_valid(&self) -> bool {
        self.encapsulated_secret.len() == 32
            && self.decapsulated_secret.len() == 32
    }

    /// Returns secrets sorted lexicographically — matching Swift's
    /// `.sorted { $0.lexicographicallyPrecedes($1) }` — for deterministic IKM construction.
    /// Both parties produce identical IKM regardless of who encapsulated first.
    pub fn sorted_secrets(&self) -> (&[u8], &[u8]) {
        if self.encapsulated_secret <= self.decapsulated_secret {
            (&self.encapsulated_secret, &self.decapsulated_secret)
        } else {
            (&self.decapsulated_secret, &self.encapsulated_secret)
        }
    }
}
```

---

### `challenge.rs`

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Protocol-level constants. Changing any value breaks compatibility
/// with all previously issued challenges.
pub struct ChallengeConstants;

impl ChallengeConstants {
    /// Domain prefix prepended to all signed payloads.
    /// Prevents cross-feature signature reuse (e.g. document signing).
    /// Must match Swift: `IdentityChallenge.domainPrefix` ("occulta-identity-challenge-v1").
    pub const DOMAIN_PREFIX: &'static [u8] = b"occulta-identity-challenge-v1";

    /// Nonce length in bytes.
    pub const NONCE_LENGTH: usize = 32;

    /// Challenger-enforced verification window in seconds.
    pub const TIMESTAMP_WINDOW_SECS: u64 = 3600;

    /// Responder soft lower bound for stale detection in seconds.
    pub const STALE_THRESHOLD_SECS: u64 = 3600;

    /// Clock skew grace period in seconds.
    pub const CLOCK_SKEW_GRACE_SECS: u64 = 30;

    /// Maximum outstanding challenges per contact (challenger-side).
    pub const MAX_OUTSTANDING_PER_CONTACT: usize = 1;

    /// Maximum context note length in UTF-8 bytes.
    pub const MAX_CONTEXT_NOTE_BYTES: usize = 500;
}

/// The 72-byte carrier for the identity challenge data.
///
/// ## Wire layout (72 bytes total — no padding)
/// ```
/// Offset  Length  Field
///      0      32  nonce                  — 32 cryptographically random bytes
///     32       8  timestamp              — UInt64 big-endian, Unix epoch seconds
///     40      32  challengerFingerprint  — SHA-256(challengerPublicKey ∥ nonce)
/// ```
///
/// ## Signing payload (101 bytes — what ECDSA actually signs)
/// `ChallengeConstants::DOMAIN_PREFIX(29) ∥ nonce(32) ∥ timestamp_be(8) ∥ challengerFingerprint(32)`
///
/// The domain prefix is NOT part of this struct — `signing_payload()` prepends it.
/// The SE signs the 101-byte output of `signing_payload()`, not the 72-byte struct.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChallengePayload {
    pub nonce:                  [u8; 32],
    /// Raw 8 big-endian bytes of Unix epoch seconds.
    /// Matches Swift `IdentityChallenge.encodeTimestamp(_:)`.
    pub timestamp_be:           [u8; 8],
    pub challenger_fingerprint: [u8; 32],   // nonce-salted; not the static key fingerprint
}

impl ChallengePayload {
    /// Encode to exactly 72 bytes: nonce ∥ timestamp_be ∥ challengerFingerprint.
    pub fn encoded(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(72);
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.timestamp_be);
        v.extend_from_slice(&self.challenger_fingerprint);
        v
    }

    /// Decode from exactly 72 bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 72 { return None; }
        let mut nonce   = [0u8; 32];
        let mut ts      = [0u8; 8];
        let mut fp      = [0u8; 32];
        nonce.copy_from_slice(&data[0..32]);
        ts.copy_from_slice(&data[32..40]);
        fp.copy_from_slice(&data[40..72]);
        Some(Self { nonce, timestamp_be: ts, challenger_fingerprint: fp })
    }

    /// Build the 101-byte blob passed to SE for ECDSA signing.
    ///
    /// Layout: DOMAIN_PREFIX(29) ∥ nonce(32) ∥ timestamp_be(8) ∥ challengerFingerprint(32)
    ///
    /// ⚠️ Pass this directly to SE signing. DO NOT pre-hash —
    /// `.ecdsaSignatureMessageX962SHA256` hashes internally.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(101);
        payload.extend_from_slice(ChallengeConstants::DOMAIN_PREFIX);
        payload.extend_from_slice(&self.nonce);
        payload.extend_from_slice(&self.timestamp_be);
        payload.extend_from_slice(&self.challenger_fingerprint);
        payload
    }
}
```

---

## Package 2: `occulta-crypto`

### Responsibility

Stateless cryptographic operations. Accepts raw bytes; returns raw bytes.
No protocol types, no wire format, no serde. Takes `info: &[u8]` as a
parameter — callers supply constants from `occulta-protocol::SaltInfo`.

### Cargo.toml

```toml
[package]
name    = "occulta-crypto"
version = "0.1.0"
edition = "2021"

[dependencies]
aes-gcm   = { version = "0.10", features = ["aes"] }
hkdf      = "0.12"
sha2      = "0.10"
p256      = { version = "0.13", features = ["ecdsa", "pkcs8"] }
rand      = { version = "0.8",  features = ["getrandom"] }
zeroize   = { version = "1.7",  features = ["derive"] }
secrecy   = "0.8"
subtle    = "2.5"
argon2    = "0.5"
thiserror = "1"
```

### Module Structure

```
occulta-crypto/src/
├── lib.rs              pub use all public items; validate_key_material()
├── error.rs            CryptoError enum
├── aes_gcm.rs          seal(), open()
├── hkdf.rs             All HKDF derivation paths
├── ecdsa.rs            verify_ecdsa() — no signing
├── shamir.rs           split(), combine() — constant-time GF(2^8)
└── kdf.rs              argon2id_derive() — replaces SHA-256 passphrase KDF
```

---

### `error.rs`

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AES-GCM seal failed")]
    SealFailed,
    #[error("AES-GCM authentication failed — tag mismatch or corrupted ciphertext")]
    AuthenticationFailed,
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("ECDSA verification failed")]
    VerificationFailed,
    #[error("HKDF expand failed")]
    HkdfFailed,
    #[error("Shamir: {0}")]
    ShamirError(String),
    #[error("Argon2 KDF failed: {0}")]
    KdfFailed(String),
    #[error("Invalid input length: {0}")]
    InvalidInput(String),
    #[error("Degenerate key material — all-zero or wrong length. SE operation may not have run.")]
    DegenerateKeyMaterial,
}
```

---

### `lib.rs` — Key-material validation

```rust
use secrecy::ExposeSecret;
use zeroize::Zeroizing;
use crate::error::CryptoError;

/// Validate that ECDH output from the SE is non-degenerate.
///
/// Rejects:
///   - Wrong length (expected 32 bytes from `ecdhKeyExchangeCofactorX963SHA256`)
///   - All-zero bytes (indicates SE operation did not run or was mocked unsafely)
///
/// Call this on every ECDH output before passing it to any HKDF function.
/// This is defense-in-depth against bypassed SE operations in testing or
/// mis-configured environments.
pub fn validate_key_material(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::DegenerateKeyMaterial);
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(CryptoError::DegenerateKeyMaterial);
    }
    Ok(())
}
```

---

### `aes_gcm.rs`

Nonce is always generated internally. Callers never supply a nonce.
Output format matches CryptoKit `.combined`: `nonce(12) ∥ ciphertext ∥ tag(16)`.

```rust
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use secrecy::{Secret, ExposeSecret};
use zeroize::Zeroizing;
use crate::error::CryptoError;

/// AES-256-GCM authenticated encryption.
///
/// - key:       32-byte AES key (HKDF output)
/// - plaintext: arbitrary length
/// - aad:       Additional Authenticated Data (OccultaBundle AAD)
///
/// Returns: nonce(12) ∥ ciphertext ∥ tag(16)
/// The nonce is generated internally via OsRng. Callers never supply a nonce.
pub fn seal(
    key:       &Secret<[u8; 32]>,
    plaintext: &[u8],
    aad:       &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::InvalidKeyLength { expected: 32, got: key.expose_secret().len() })?;

    let nonce   = Aes256Gcm::generate_nonce(OsRng);
    let payload = aes_gcm::aead::Payload { msg: plaintext, aad };

    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::SealFailed)?;

    // Prepend nonce — matches CryptoKit .combined format
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(nonce.as_slice());
    combined.extend_from_slice(&ciphertext);
    Ok(combined)
}

/// AES-256-GCM authenticated decryption.
///
/// - key:      32-byte AES key
/// - combined: nonce(12) ∥ ciphertext ∥ tag(16) — as produced by seal()
/// - aad:      Must be identical to what was passed to seal()
///
/// Returns: plaintext bytes, or AuthenticationFailed if the tag does not verify.
/// Never returns partial plaintext.
pub fn open(
    key:      &Secret<[u8; 32]>,
    combined: &[u8],
    aad:      &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if combined.len() < 12 + 16 {
        return Err(CryptoError::InvalidInput(
            format!("combined too short: {} bytes", combined.len())
        ));
    }

    let (nonce_bytes, rest) = combined.split_at(12);
    let nonce  = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key.expose_secret())
        .map_err(|_| CryptoError::InvalidKeyLength { expected: 32, got: key.expose_secret().len() })?;

    let payload = aes_gcm::aead::Payload { msg: rest, aad };
    cipher
        .decrypt(nonce, payload)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}
```

---

### `hkdf.rs`

All HKDF paths from the Swift codebase, expressed as pure functions.
Each function documents which SaltInfo constant to pass as `info`.

**Important:** The `ikm` parameter is the output of `SecKeyCopyKeyExchangeResult`
with algorithm `.ecdhKeyExchangeCofactorX963SHA256`. This is a 32-byte value
produced by: ECDH shared point x-coordinate → X9.63 Key Derivation Function with
SHA-256. It is **not** the raw ECDH x-coordinate. Always call `validate_key_material()`
on this value before passing it here.

```rust
use hkdf::Hkdf;
use sha2::Sha256;
use secrecy::{Secret, ExposeSecret};
use zeroize::Zeroizing;
use crate::error::CryptoError;

/// Classical HKDF derivation.
///
/// Path: SE_X963_KDF_output → HKDF-SHA256 → 32-byte AES key
///
/// - ikm:  32-byte output of `ecdhKeyExchangeCofactorX963SHA256` from SE.
///         Call `validate_key_material(ikm)` before passing here.
/// - salt: XOR(peerPublicKey_x963, ourPublicKey_x963) — 65 bytes each, XORed byte-by-byte
/// - info: SaltInfo::TRANSPORT or SaltInfo::LOCAL_DB depending on context
///
/// Matches Swift: HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:32)
pub fn derive(
    ikm:  &Secret<Vec<u8>>,
    salt: &[u8],
    info: &[u8],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm.expose_secret());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::HkdfFailed)?;
    Ok(Secret::new(okm))
}

/// Hybrid IKM construction and derivation.
///
/// Path: (SE_X963_KDF_output ∥ sorted(ML-KEM_A, ML-KEM_B)) → HKDF-SHA256 → 32-byte key
///
/// - ecdh_raw:       32-byte X9.63-KDF output from SE. Not the raw ECDH x-coordinate.
///                   Call `validate_key_material(ecdh_raw)` before passing here.
/// - mlkem_secret_a: ML-KEM shared secret — encapsulatedSecret
/// - mlkem_secret_b: ML-KEM shared secret — decapsulatedSecret
/// - salt:           XOR(peerP256Pub, ourP256Pub) — 65 bytes each
/// - info:           SaltInfo::HYBRID_TRANSPORT or SaltInfo::HYBRID_FS_TRANSPORT
///
/// Secrets are sorted lexicographically before concatenation — identical to Swift's
/// `.sorted { $0.lexicographicallyPrecedes($1) }` — so both peers produce the same IKM
/// regardless of who encapsulated first.
pub fn derive_hybrid(
    ecdh_raw:       &Secret<Vec<u8>>,
    mlkem_secret_a: &Secret<Vec<u8>>,
    mlkem_secret_b: &Secret<Vec<u8>>,
    salt:           &[u8],
    info:           &[u8],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    // Sort secrets lexicographically — must match Swift sort order exactly
    let (first, second) = if mlkem_secret_a.expose_secret() <= mlkem_secret_b.expose_secret() {
        (mlkem_secret_a.expose_secret(), mlkem_secret_b.expose_secret())
    } else {
        (mlkem_secret_b.expose_secret(), mlkem_secret_a.expose_secret())
    };

    let mut ikm = Zeroizing::new(Vec::with_capacity(
        ecdh_raw.expose_secret().len() + first.len() + second.len()
    ));
    ikm.extend_from_slice(ecdh_raw.expose_secret());
    ikm.extend_from_slice(first);
    ikm.extend_from_slice(second);

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::HkdfFailed)?;
    Ok(Secret::new(okm))
}

/// Hybrid local DB key derivation.
///
/// Path: (SE_X963_KDF_output ∥ Keychain_random_32B) → HKDF-SHA256 → 32-byte key
///
/// - se_component:     32-byte `ecdhKeyExchangeCofactorX963SHA256` output (SE priv, G).
///                     This is X9.63/SHA-256 of ECDH(localDB_SE_priv, G).
/// - random_component: 32-byte value from Keychain (generated and stored by Swift)
/// - salt:             localDB SE public key x963 (65 bytes)
/// - info:             SaltInfo::HYBRID_LOCAL_DB
///
/// An attacker needs both the SE and the Keychain to derive this key.
pub fn derive_hybrid_local_db(
    se_component:     &Secret<Vec<u8>>,
    random_component: &Secret<Vec<u8>>,
    salt:             &[u8],
    info:             &[u8],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        se_component.expose_secret().len() + random_component.expose_secret().len()
    ));
    ikm.extend_from_slice(se_component.expose_secret());
    ikm.extend_from_slice(random_component.expose_secret());

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).map_err(|_| CryptoError::HkdfFailed)?;
    Ok(Secret::new(okm))
}

/// Diceware verification key derivation.
///
/// Identical hybrid IKM to derive_hybrid(), but the info field includes
/// sorted exchange nonces for per-session uniqueness.
///
/// - info_prefix: SaltInfo::DICEWARE_PREFIX
/// - nonce_a, nonce_b: 16-byte exchange nonces (one per peer)
///   Sorted and appended to prefix — matches Swift's sorted nonce construction.
pub fn derive_diceware(
    ecdh_raw:       &Secret<Vec<u8>>,
    mlkem_secret_a: &Secret<Vec<u8>>,
    mlkem_secret_b: &Secret<Vec<u8>>,
    salt:           &[u8],
    info_prefix:    &[u8],      // SaltInfo::DICEWARE_PREFIX
    nonce_a:        &[u8; 16],
    nonce_b:        &[u8; 16],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    // Sorted nonces — matches Swift `.sorted { $0.lexicographicallyPrecedes($1) }`
    let (first_nonce, second_nonce) = if nonce_a <= nonce_b {
        (nonce_a.as_slice(), nonce_b.as_slice())
    } else {
        (nonce_b.as_slice(), nonce_a.as_slice())
    };

    let mut info = Zeroizing::new(Vec::with_capacity(
        info_prefix.len() + 16 + 16
    ));
    info.extend_from_slice(info_prefix);
    info.extend_from_slice(first_nonce);
    info.extend_from_slice(second_nonce);

    derive_hybrid(ecdh_raw, mlkem_secret_a, mlkem_secret_b, salt, &info)
}

/// Compute XOR salt from two X9.63 public keys.
///
/// salt = byte-wise XOR(a, b) where a and b are 65-byte X9.63 public keys.
/// Matches Swift: Data(zip(peerMaterial, ourPubData).map { $0 ^ $1 })
pub fn xor_salt(a: &[u8; 65], b: &[u8; 65]) -> [u8; 65] {
    let mut salt = [0u8; 65];
    for i in 0..65 {
        salt[i] = a[i] ^ b[i];
    }
    salt
}
```

---

### `ecdsa.rs`

Verification only. Signing is always performed by the Secure Enclave in Swift.
Never receives a private key.

```rust
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use crate::error::CryptoError;

/// Verify an ECDSA-SHA256 signature against a P-256 public key.
///
/// - public_key_x963: 65-byte X9.63 uncompressed P-256 public key
/// - message:         Original message bytes — NOT pre-hashed
///                    ⚠️ DO NOT pre-hash. p256 hashes internally (SHA-256).
///                    Matches Swift: .ecdsaSignatureMessageX962SHA256
/// - signature_der:   DER-encoded ECDSA signature from SE
///
/// Returns Ok(()) if valid, Err(VerificationFailed) otherwise.
pub fn verify(
    public_key_x963: &[u8; 65],
    message:         &[u8],
    signature_der:   &[u8],
) -> Result<(), CryptoError> {
    let point = EncodedPoint::from_bytes(public_key_x963)
        .map_err(|_| CryptoError::InvalidInput("invalid X9.63 public key".into()))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| CryptoError::InvalidInput("cannot construct verifying key".into()))?;
    let signature = Signature::from_der(signature_der)
        .map_err(|_| CryptoError::InvalidInput("invalid DER signature".into()))?;

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}
```

---

### `shamir.rs`

Implementation over GF(2^8) using the irreducible polynomial
`x^8 + x^4 + x^3 + x + 1` (**0x11B** — the AES field), matching
`ShamirSecretSharing.swift` exactly. The reduction constant applied when the
high bit overflows during multiplication is `0x1B` (the low 8 bits of `0x11B`).

**⚠️ Polynomial invariant:** Using any polynomial other than `0x11B` produces
shares that are silently incompatible with Swift. `shamir_combine` on the Rust
side will return garbage from shares generated by Swift and vice versa —
no error is raised. The interoperability round-trip test vector catches this
immediately.

**Share wire format:** Each share is exactly **33 bytes**:
- `share[0]` — x-coordinate, range `[1, n]` (1-based)
- `share[1..=32]` — GF(2^8) polynomial evaluations for each of the 32 secret bytes

Secret must be exactly 32 bytes (vault key material). `split()` rejects any
other length with `ShamirError`.

**GF(2^8) arithmetic approach:**

| Operation | Method | Why |
|---|---|---|
| `gf_mul(a, b)` | Russian peasant, fixed 8-iteration loop | Matches Swift; loop count is constant regardless of input — no secret-dependent branch on *count* |
| `gf_inv(a)` | Fermat: `a^254` via `gf_mul` squaring | Matches Swift `gfInv`; `|GF(2^8)*| = 255`, so `a^255 = 1`, `a^254 = a^(−1)` |
| `eval(poly, x)` | Horner's method | Matches Swift; `O(k)` instead of `O(k²)` |
| `lagrange(xs, ys)` | Interpolation at `x=0` | `f(0)` is the secret byte |

Note on constant-time: the Russian peasant `gf_mul` iterates exactly 8 times
and its conditional branches (`if carry`, `if b & 1`) operate on intermediate
multiply state, not directly on secret bytes. This matches the Swift
implementation. For a stricter constant-time requirement, replace with
log/antilog table lookup — both approaches use the same `0x11B` field.

```rust
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand::RngCore;
use crate::error::CryptoError;

/// Split a 32-byte secret into `n` shares requiring `k` to reconstruct.
///
/// Secret must be exactly 32 bytes — matches Swift's `invalidSecretLength` guard.
/// Each share is exactly 33 bytes: `x_coordinate(1) ∥ y_values(32)`.
///
/// Uses `rand::thread_rng()` for coefficient generation.
/// The leading coefficient of each polynomial is guaranteed non-zero,
/// ensuring the polynomial has exactly degree (k−1).
///
/// ⚠️ Caller must zero the `secret` buffer after this call returns.
pub fn split(
    secret: &[u8],
    n: u8,
    k: u8,
) -> Result<Vec<Zeroizing<Vec<u8>>>, CryptoError> {
    if k < 2 || n < k || n == 0 {
        return Err(CryptoError::ShamirError(
            format!("invalid threshold: k={k}, n={n}")
        ));
    }
    if secret.len() != 32 {
        return Err(CryptoError::ShamirError(
            format!("secret must be exactly 32 bytes, got {}", secret.len())
        ));
    }
    gf_split(secret, n, k)
}

/// Reconstruct the 32-byte secret from k or more shares.
///
/// Each share must be exactly 33 bytes: `x_coordinate(1) ∥ y_values(32)`.
/// Duplicate x-coordinates are rejected. x=0 is rejected (would trivially
/// expose the secret without meeting the threshold).
///
/// ⚠️ Caller must zero the returned buffer immediately after re-encrypting.
pub fn combine(
    shares: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if shares.len() < 2 {
        return Err(CryptoError::ShamirError("insufficient shares".into()));
    }
    if shares.iter().any(|s| s.len() != 33) {
        return Err(CryptoError::ShamirError(
            "each share must be exactly 33 bytes".into()
        ));
    }
    let x_coords: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    if x_coords.iter().any(|&x| x == 0) {
        return Err(CryptoError::ShamirError("x=0 share is invalid".into()));
    }
    // Duplicate x-coordinate check — Lagrange is undefined if two shares share x.
    let mut seen = std::collections::HashSet::new();
    for &x in &x_coords {
        if !seen.insert(x) {
            return Err(CryptoError::ShamirError("duplicate x-coordinate".into()));
        }
    }
    gf_combine(shares)
}

// ── GF(2^8) arithmetic ────────────────────────────────────────────────────────
//
// Primitive polynomial: x^8 + x^4 + x^3 + x + 1  (0x11B — the AES field).
// Reduction constant: 0x1B = x^4 + x^3 + x + 1  (applied on high-bit overflow).
//
// ⚠️ Must match Swift's ShamirSecretSharing.swift exactly.
//    If you change the polynomial, all existing shares become unreadable.

/// Multiply two GF(2^8) elements using the Russian peasant algorithm.
/// Fixed 8-iteration loop — constant iteration count regardless of input.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry { a ^= 0x1B; }   // reduce: x^8 mod 0x11B ≡ 0x1B
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(2^8) via Fermat's little theorem: a^254.
/// |GF(2^8)*| = 255, so a^255 = 1, therefore a^(−1) = a^254.
/// Precondition: a ≠ 0.
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "zero has no multiplicative inverse in GF(2^8)");
    let mut result: u8 = 1;
    let mut base = a;
    let mut exp: u32 = 254;
    while exp > 0 {
        if exp & 1 != 0 { result = gf_mul(result, base); }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

/// Evaluate polynomial `coeffs` at `x` using Horner's method in GF(2^8).
/// `coeffs[0]` is the constant term (the secret byte).
fn gf_eval(coeffs: &[u8], x: u8) -> u8 {
    coeffs.iter().rev().fold(0u8, |acc, &c| gf_mul(acc, x) ^ c)
}

/// Lagrange interpolation at x=0 over GF(2^8).
/// f(0) = Σᵢ [ yᵢ · ∏ⱼ≠ᵢ xⱼ / (xᵢ ⊕ xⱼ) ]
/// In GF(2^8): subtraction = XOR, (0 − xⱼ) = xⱼ.
fn gf_lagrange(x_coords: &[u8], y_coords: &[u8]) -> u8 {
    let mut secret: u8 = 0;
    for i in 0..x_coords.len() {
        let mut num: u8 = y_coords[i];
        let mut den: u8 = 1;
        for j in 0..x_coords.len() {
            if i == j { continue; }
            num = gf_mul(num, x_coords[j]);
            den = gf_mul(den, x_coords[i] ^ x_coords[j]);
        }
        secret ^= gf_mul(num, gf_inv(den));
    }
    secret
}

fn gf_split(secret: &[u8], n: u8, k: u8) -> Result<Vec<Zeroizing<Vec<u8>>>, CryptoError> {
    let mut rng = rand::thread_rng();
    // Pre-allocate n shares, each 33 bytes: [x_coord, y0, y1, ..., y31]
    let mut shares: Vec<Zeroizing<Vec<u8>>> = (1..=n)
        .map(|x| {
            let mut s = Zeroizing::new(vec![0u8; 33]);
            s[0] = x;
            s
        })
        .collect();

    // For each of the 32 secret bytes, build an independent degree-(k−1) polynomial.
    for byte_idx in 0..32 {
        // coeffs[0] = secret byte; coeffs[1..k−1] = random; leading coeff ≠ 0.
        let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
        coeffs[0] = secret[byte_idx];
        for i in 1..(k as usize) {
            loop {
                rng.fill_bytes(&mut coeffs[i..=i]);
                // Leading coefficient must be non-zero to ensure exactly degree k−1.
                if i != (k as usize - 1) || coeffs[i] != 0 { break; }
            }
        }
        for (share_idx, share) in shares.iter_mut().enumerate() {
            share[byte_idx + 1] = gf_eval(&coeffs, share[0]);
        }
    }
    Ok(shares)
}

fn gf_combine(shares: &[Vec<u8>]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let x_coords: Vec<u8> = shares.iter().map(|s| s[0]).collect();
    let mut secret = Zeroizing::new(vec![0u8; 32]);
    for byte_idx in 0..32 {
        let y_coords: Vec<u8> = shares.iter().map(|s| s[byte_idx + 1]).collect();
        secret[byte_idx] = gf_lagrange(&x_coords, &y_coords);
    }
    Ok(secret)
}
```

---

### `kdf.rs`

Replaces the existing `SHA256(passphrase.utf8)` passphrase derivation.
This is a breaking change — requires a version byte in the export format.

```rust
use argon2::{Argon2, Params, Version as ArgonVersion, Algorithm};
use secrecy::{Secret, ExposeSecret};
use crate::error::CryptoError;

/// Export format version byte.
/// 0x01 = legacy SHA-256 (read-only for migration)
/// 0x02 = Argon2id (current write path)
pub const EXPORT_VERSION_SHA256:   u8 = 0x01;
pub const EXPORT_VERSION_ARGON2ID: u8 = 0x02;

/// Argon2id parameters — tuned for ~200ms on a mid-range iPhone.
pub const ARGON2_M_COST:  u32  = 65536;   // 64 MiB memory
pub const ARGON2_T_COST:  u32  = 3;       // 3 iterations
pub const ARGON2_P_COST:  u32  = 4;       // 4 parallelism lanes
pub const ARGON2_OUTPUT:  usize = 32;     // 32-byte AES key

/// Derive a 32-byte AES key from a passphrase using Argon2id.
///
/// - passphrase: User-supplied passphrase
/// - salt:       16-byte random salt (caller generates, stores with export).
///               Must not be reused across different passphrases.
///
/// Replaces: SHA256(passphrase.data(using: .utf8)!) in Crypto+Manager.swift
pub fn argon2id_derive(
    passphrase: &Secret<String>,
    salt: &[u8; 16],
) -> Result<Secret<[u8; 32]>, CryptoError> {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_OUTPUT))
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut okm = [0u8; 32];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut okm)
        .map_err(|e| CryptoError::KdfFailed(e.to_string()))?;
    Ok(Secret::new(okm))
}
```

**Migration path for existing exports:**
```
export_format:
  [version_byte(1)] [payload...]
version 0x01: [0x01][aes_gcm_combined]
  key = SHA256(passphrase.utf8) — read-only, existing exports
version 0x02: [0x02][salt(16)][aes_gcm_combined]
  key = Argon2id(passphrase, salt, params above)
```

---

## Package 3: `occulta-ffi`

### Responsibility

UniFFI binding layer only. Contains no logic beyond chaining calls from
`occulta-protocol` and `occulta-crypto`. Produces the `.xcframework`.

### Cargo.toml

```toml
[package]
name    = "occulta-ffi"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "staticlib"]

[dependencies]
occulta-protocol = { path = "../occulta-protocol" }
occulta-crypto   = { path = "../occulta-crypto" }
uniffi           = { version = "0.27", features = ["tokio"] }
thiserror        = "1"

[build-dependencies]
uniffi = { version = "0.27", features = ["build"] }
```

### Directory Structure

```
occulta-ffi/
├── Cargo.toml
├── build.rs
├── occulta_ffi.udl        UniFFI interface definition
└── src/
    ├── lib.rs             #[uniffi::export] wrappers + SE capability registration
    └── error.rs           OccultaError — unified error type for FFI
```

---

### `error.rs`

```rust
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum OccultaError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed — authentication tag mismatch or corrupted data")]
    DecryptionFailed,
    #[error("HKDF derivation failed")]
    DerivationFailed,
    #[error("ECDSA verification failed")]
    VerificationFailed,
    #[error("Shamir: {message}")]
    ShamirError { message: String },
    #[error("KDF failed: {message}")]
    KdfFailed { message: String },
    #[error("Protocol error: {message}")]
    ProtocolError { message: String },
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    #[error("Device does not have a Secure Enclave or equivalent secure key storage")]
    NoSecureKeyStorage,
    #[error("Degenerate key material — SE operation may not have run")]
    DegenerateKeyMaterial,
}
```

---

### `occulta_ffi.udl`

UniFFI UDL error variants with associated data use the `interface` form,
not the `enum` form.

```
namespace occulta_ffi {};

// ── Errors ────────────────────────────────────────────────────────────────────
[Error]
interface OccultaError {
    EncryptionFailed();
    DecryptionFailed();
    DerivationFailed();
    VerificationFailed();
    ShamirError(string message);
    KdfFailed(string message);
    ProtocolError(string message);
    InvalidInput(string message);
    NoSecureKeyStorage();
    DegenerateKeyMaterial();
};

// ── Platform capabilities ──────────────────────────────────────────────────────
//
// Swift registers an implementation of PlatformCapabilityProvider at startup.
// Call register_platform_capabilities() before any key-derivation or AES-GCM
// function. Call assert_secure_key_storage() as a precondition gate.
//
// Swift implementation uses SecureEnclave.isAvailable (CryptoKit) or equivalent.
callback interface PlatformCapabilityProvider {
    /// Return true if the device has a Secure Enclave or equivalent hardware
    /// key storage (T1/T2 chip, Titan M equivalent, etc.).
    boolean has_secure_key_storage();
};

void register_platform_capabilities(PlatformCapabilityProvider provider);

/// Assert that the device has secure key storage.
/// Throws NoSecureKeyStorage if not registered or the provider returns false.
/// Call once at app startup; abort initialisation on failure.
[Throws=OccultaError]
void assert_secure_key_storage();

// ── AES-256-GCM ──────────────────────────────────────────────────────────────
// Nonce is always generated internally. Never caller-supplied.
// Output: nonce(12) ∥ ciphertext ∥ tag(16) — matches CryptoKit .combined format.
[Throws=OccultaError]
bytes aes_gcm_seal(bytes key, bytes plaintext, bytes aad);

[Throws=OccultaError]
bytes aes_gcm_open(bytes key, bytes combined, bytes aad);

// ── Key-material validation ───────────────────────────────────────────────────
// Call before any HKDF function. Rejects all-zero and wrong-length IKM.
[Throws=OccultaError]
void validate_key_material(bytes key_material);

// ── HKDF ─────────────────────────────────────────────────────────────────────
// ikm: 32-byte X9.63-KDF output from SE (ecdhKeyExchangeCofactorX963SHA256)
// salt: XOR(peerPub_x963, ourPub_x963) — 65 bytes each
// info: SaltInfo constant bytes
[Throws=OccultaError]
bytes hkdf_derive(bytes ikm, bytes salt, bytes info);

// Hybrid: ECDH + ML-KEM. Secrets sorted internally — callers pass unsorted.
[Throws=OccultaError]
bytes hkdf_derive_hybrid(
    bytes ecdh_raw,
    bytes mlkem_secret_a,
    bytes mlkem_secret_b,
    bytes salt,
    bytes info
);

// Hybrid local DB: SE component + Keychain random component
[Throws=OccultaError]
bytes hkdf_derive_hybrid_local_db(
    bytes se_component,
    bytes random_component,
    bytes salt,
    bytes info
);

// Diceware: hybrid IKM + sorted nonces appended to info prefix
[Throws=OccultaError]
bytes hkdf_derive_diceware(
    bytes ecdh_raw,
    bytes mlkem_secret_a,
    bytes mlkem_secret_b,
    bytes salt,
    bytes info_prefix,
    bytes nonce_a,
    bytes nonce_b
);

// XOR salt: byte-wise XOR of two 65-byte X9.63 public keys
[Throws=OccultaError]
bytes xor_salt(bytes pub_key_a, bytes pub_key_b);

// ── ECDSA ─────────────────────────────────────────────────────────────────────
// Verify-only. Signing is always performed by the Secure Enclave in Swift.
// message: NOT pre-hashed — p256 applies SHA-256 internally.
[Throws=OccultaError]
void ecdsa_verify(bytes public_key_x963, bytes message, bytes signature_der);

// ── Shamir SSS ────────────────────────────────────────────────────────────────
// Each share in the returned sequence is encoded as:
//   x_coordinate(1 byte) ∥ share_data(N bytes)
// where x_coordinate is the 1-based share index. shamir_combine() expects
// the same format — first byte is the x-coordinate.
[Throws=OccultaError]
sequence<bytes> shamir_split(bytes secret, u8 n, u8 k);

[Throws=OccultaError]
bytes shamir_combine(sequence<bytes> shares);

// ── Wire format ───────────────────────────────────────────────────────────────
[Throws=OccultaError]
bytes bundle_encode(bytes bundle_json);

[Throws=OccultaError]
bytes bundle_decode(bytes data);

// AAD computation — must match Swift's JSONEncoder .sortedKeys output byte-for-byte
[Throws=OccultaError]
bytes bundle_compute_aad(bytes version_raw_utf8, bytes secrecy_json);

// Fingerprint: SHA-256(sender_pub_x963(65) ∥ fingerprint_nonce(16))
[Throws=OccultaError]
bytes bundle_compute_fingerprint(bytes sender_public_key_x963, bytes fingerprint_nonce);

// ── Identity Challenge ────────────────────────────────────────────────────────
// Build the 101-byte signing payload: DOMAIN_PREFIX(29) ∥ nonce(32) ∥ timestamp_be(8) ∥ fingerprint(32)
// Pass the result directly to SE signing — DO NOT pre-hash.
[Throws=OccultaError]
bytes challenge_signing_payload(bytes nonce, bytes timestamp_be, bytes challenger_fingerprint);

// Verify a challenge response
[Throws=OccultaError]
void challenge_verify(
    bytes signing_payload,
    bytes signature_der,
    bytes responder_public_key_x963
);

// ── Passphrase KDF ────────────────────────────────────────────────────────────
// Argon2id — replaces SHA-256. salt: 16 random bytes (caller-generated, stored with export)
[Throws=OccultaError]
bytes argon2id_derive(string passphrase, bytes salt);

// ── SaltInfo constants ────────────────────────────────────────────────────────
// Exposed so Swift can reference them without hardcoding.
bytes salt_info_transport();
bytes salt_info_local_db();
bytes salt_info_hybrid_local_db();
bytes salt_info_hybrid_transport();
bytes salt_info_hybrid_fs_transport();
bytes salt_info_diceware_prefix();
bytes salt_info_vault();
bytes salt_info_shard_custody();
bytes salt_info_secure_mode_pin();
bytes salt_info_recovery_buffer();
```

---

### `src/lib.rs` (excerpt)

```rust
uniffi::include_scaffolding!("occulta_ffi");

use std::sync::{Arc, OnceLock};
use occulta_crypto::{aes_gcm, hkdf, ecdsa, shamir, kdf, validate_key_material as _validate};
use occulta_protocol::{bundle, salt_info::SaltInfo, challenge::ChallengeConstants};
use secrecy::Secret;
use crate::error::OccultaError;

// ── Platform capability gate ───────────────────────────────────────────────────

static PLATFORM: OnceLock<Arc<dyn PlatformCapabilityProvider>> = OnceLock::new();

#[uniffi::export]
pub fn register_platform_capabilities(provider: Arc<dyn PlatformCapabilityProvider>) {
    // OnceLock::set silently ignores a second call — first registration wins.
    PLATFORM.set(provider).ok();
}

#[uniffi::export]
pub fn assert_secure_key_storage() -> Result<(), OccultaError> {
    std::panic::catch_unwind(|| {
        match PLATFORM.get() {
            Some(p) if p.has_secure_key_storage() => Ok(()),
            Some(_) => Err(OccultaError::NoSecureKeyStorage),
            None    => Err(OccultaError::NoSecureKeyStorage),
        }
    })
    .map_err(|_| OccultaError::NoSecureKeyStorage)?
}

// ── Key-material validation ────────────────────────────────────────────────────

#[uniffi::export]
pub fn validate_key_material(key_material: Vec<u8>) -> Result<(), OccultaError> {
    std::panic::catch_unwind(|| {
        _validate(&key_material).map_err(|_| OccultaError::DegenerateKeyMaterial)
    })
    .map_err(|_| OccultaError::DegenerateKeyMaterial)?
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

#[uniffi::export]
pub fn aes_gcm_seal(
    key:       Vec<u8>,
    plaintext: Vec<u8>,
    aad:       Vec<u8>,
) -> Result<Vec<u8>, OccultaError> {
    std::panic::catch_unwind(|| {
        let key_arr: [u8; 32] = key.try_into()
            .map_err(|_| OccultaError::InvalidInput { message: "key must be 32 bytes".into() })?;
        aes_gcm::seal(&Secret::new(key_arr), &plaintext, &aad)
            .map_err(|_| OccultaError::EncryptionFailed)
    })
    .map_err(|_| OccultaError::EncryptionFailed)?
}

// ── challenge_signing_payload ──────────────────────────────────────────────────

#[uniffi::export]
pub fn challenge_signing_payload(
    nonce:                  Vec<u8>,   // 32 bytes
    timestamp_be:           Vec<u8>,   // 8 bytes, big-endian UInt64
    challenger_fingerprint: Vec<u8>,   // 32 bytes
) -> Result<Vec<u8>, OccultaError> {
    std::panic::catch_unwind(|| {
        let n: [u8; 32] = nonce.try_into()
            .map_err(|_| OccultaError::InvalidInput { message: "nonce must be 32 bytes".into() })?;
        let t: [u8; 8]  = timestamp_be.try_into()
            .map_err(|_| OccultaError::InvalidInput { message: "timestamp must be 8 bytes".into() })?;
        let f: [u8; 32] = challenger_fingerprint.try_into()
            .map_err(|_| OccultaError::InvalidInput { message: "fingerprint must be 32 bytes".into() })?;

        let payload = occulta_protocol::challenge::ChallengePayload {
            nonce: n, timestamp_be: t, challenger_fingerprint: f,
        };
        Ok(payload.signing_payload())
    })
    .map_err(|_| OccultaError::InvalidInput { message: "panic in challenge_signing_payload".into() })?
}

// ... remaining functions follow the same catch_unwind pattern
```

---

## Interoperability Test Vectors

Before switching any Swift call site to Rust, extract exact byte outputs from
the Swift test suite and assert Rust produces identical bytes.

### Required Vectors

| Test | Input | Expected output |
|---|---|---|
| `hkdf_derive` classical | Known ECDH bytes + known salt + `kTransportKeyInfo` | 32-byte key from Swift |
| `hkdf_derive_hybrid` | Known ECDH + known ML-KEM secrets + known salt | 32-byte key from Swift |
| `aes_gcm` round-trip | Known key + known plaintext + known aad | Plaintext recovered |
| `bundle_compute_aad` | Version `.v3fs` + known SecrecyContext JSON | AAD bytes from Swift |
| `bundle_compute_aad` | Version `.v1` + longTermFallback context | AAD bytes from Swift |
| `bundle_fingerprint` | Known 65-byte pubkey + known 16-byte nonce | 32-byte SHA-256 from Swift |
| `bundle encode/decode` | Full OccultaBundle struct | Byte-identical JSON roundtrip |
| `challenge_signing_payload` | Known nonce(32) + timestamp_be(8) + fingerprint(32) | 101-byte blob identical to Swift `buildSignedData` |
| `shamir split/combine` | Known 32-byte secret, n=5, k=3 | Secret recovered; x-coord byte verified |
| `xor_salt` | Two known 65-byte keys | XOR output from Swift |

Place vectors in `occulta-ffi/tests/interop_vectors.rs`.
These are the acceptance gate — no PR merges that changes any vector output.

**Critical AAD vector note:** Extract `computeAdditionalAuthentication(version:secrecy:)`
output from `OccultaBundleTests` with a fixed `SecrecyContext` where `prekeyID` is
non-nil. Verify the Rust output matches byte-for-byte, paying special attention to
`"prekeyID"` (capital I, capital D) in the JSON. Run this test before any other.

---

## Migration Order

Each step: validate against interop vectors → switch one Swift call site →
delete the corresponding Swift implementation → ship.

| Step | What moves | Validation gate |
|---|---|---|
| 1 | `SaltInfo` constants | Unit test all 10 constant byte values |
| 2 | `shamir_split` / `shamir_combine` | Round-trip test + x-coord encoding verified + no-secret-dependent-branch audit |
| 3 | `xor_salt` | Byte-match with Swift output |
| 4 | `hkdf_derive` classical path | Interop vector match |
| 5 | `hkdf_derive_hybrid` all variants | Interop vector match for all 4 paths |
| 6 | `aes_gcm_seal` / `aes_gcm_open` | Round-trip + interop vector |
| 7 | `bundle_compute_aad` | Most critical — byte-exact match required, especially `prekeyID` key casing |
| 8 | `bundle_encode` / `bundle_decode` | Full bundle round-trip across Swift and Rust |
| 9 | `challenge_signing_payload` + `ecdsa_verify` | Challenge round-trip test |
| 10 | `argon2id_derive` | New only — no existing interop; add version byte to export format |

Step 7 is the highest risk. Run it independently with a dedicated review
before proceeding to step 8.

---

## Build Script — `scripts/build-xcframework.sh`

```bash
#!/bin/bash
# scripts/build-xcframework.sh
#
# Builds occulta-ffi for iOS device + simulator, creates xcframework,
# generates UniFFI Swift bindings, and assembles an SPM-ready Swift Package.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   cargo install uniffi-bindgen
#
# Usage:
#   ./scripts/build-xcframework.sh            # release build
#   ./scripts/build-xcframework.sh debug      # debug build

set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CRATE_DIR="$ROOT_DIR/occulta-ffi"
LIB_NAME="occulta_ffi"
FRAMEWORK_NAME="OccultaCoreFFI"
OUTPUT_PACKAGE="$ROOT_DIR/OccultaSDK"
PROFILE="${1:-release}"

if [ "$PROFILE" = "release" ]; then
    CARGO_FLAGS="--release"
    BUILD_DIR="release"
else
    CARGO_FLAGS=""
    BUILD_DIR="debug"
fi

TARGET_DIR="$CRATE_DIR/target"
BINDINGS_DIR="$TARGET_DIR/bindings"
HEADERS_DIR="$TARGET_DIR/headers"

echo "▸ [1/6] Compiling — aarch64-apple-ios (device)"
cargo build \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target aarch64-apple-ios \
    $CARGO_FLAGS

echo "▸ [1/6] Compiling — aarch64-apple-ios-sim (Apple Silicon simulator)"
cargo build \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target aarch64-apple-ios-sim \
    $CARGO_FLAGS

echo "▸ [1/6] Compiling — x86_64-apple-ios (Intel simulator)"
cargo build \
    --manifest-path "$CRATE_DIR/Cargo.toml" \
    --target x86_64-apple-ios \
    $CARGO_FLAGS

echo "▸ [2/6] Merging simulator slices (lipo)"
mkdir -p "$TARGET_DIR/sim-universal/$BUILD_DIR"
lipo -create \
    "$TARGET_DIR/aarch64-apple-ios-sim/$BUILD_DIR/lib${LIB_NAME}.a" \
    "$TARGET_DIR/x86_64-apple-ios/$BUILD_DIR/lib${LIB_NAME}.a" \
    -output "$TARGET_DIR/sim-universal/$BUILD_DIR/lib${LIB_NAME}.a"
lipo -info "$TARGET_DIR/sim-universal/$BUILD_DIR/lib${LIB_NAME}.a"

echo "▸ [3/6] Generating Swift bindings via uniffi-bindgen"
mkdir -p "$BINDINGS_DIR"
uniffi-bindgen generate \
    --library "$TARGET_DIR/aarch64-apple-ios/$BUILD_DIR/lib${LIB_NAME}.a" \
    --language swift \
    --out-dir "$BINDINGS_DIR"

[ -f "$BINDINGS_DIR/${FRAMEWORK_NAME}.h" ]        || { echo "ERROR: header not generated"; exit 1; }
[ -f "$BINDINGS_DIR/${FRAMEWORK_NAME}.modulemap" ] || { echo "ERROR: modulemap not generated"; exit 1; }
[ -f "$BINDINGS_DIR/OccultaCore.swift" ]           || { echo "ERROR: Swift bindings not generated"; exit 1; }

echo "▸ [4/6] Assembling headers"
mkdir -p "$HEADERS_DIR"
cp "$BINDINGS_DIR/${FRAMEWORK_NAME}.h"        "$HEADERS_DIR/"
cp "$BINDINGS_DIR/${FRAMEWORK_NAME}.modulemap" "$HEADERS_DIR/module.modulemap"

echo "▸ [5/6] Creating xcframework"
rm -rf "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework"
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/aarch64-apple-ios/$BUILD_DIR/lib${LIB_NAME}.a" \
    -headers "$HEADERS_DIR/" \
    -library "$TARGET_DIR/sim-universal/$BUILD_DIR/lib${LIB_NAME}.a" \
    -headers "$HEADERS_DIR/" \
    -output "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework"

[ -d "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework/ios-arm64" ]           || { echo "ERROR: device slice missing"; exit 1; }
[ -d "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework/ios-arm64-simulator" ] || { echo "ERROR: simulator slice missing"; exit 1; }

echo "▸ [6/6] Assembling Swift Package at OccultaSDK/"
rm -rf "$OUTPUT_PACKAGE"
mkdir -p "$OUTPUT_PACKAGE/Sources/OccultaCore"
cp "$BINDINGS_DIR/OccultaCore.swift" "$OUTPUT_PACKAGE/Sources/OccultaCore/"
cp -r "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework" "$OUTPUT_PACKAGE/"

cat > "$OUTPUT_PACKAGE/Package.swift" << 'PACKAGE'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OccultaCore",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "OccultaCore", targets: ["OccultaCore"]),
    ],
    targets: [
        .target(
            name: "OccultaCore",
            dependencies: ["OccultaCoreFFI"],
            path: "Sources/OccultaCore"
        ),
        .binaryTarget(
            name: "OccultaCoreFFI",
            path: "OccultaCoreFFI.xcframework"
        ),
    ]
)
PACKAGE

echo ""
echo "✓ Build complete"
echo ""
echo "  Device library:    $(du -sh "$TARGET_DIR/aarch64-apple-ios/$BUILD_DIR/lib${LIB_NAME}.a" | cut -f1)"
echo "  Simulator library: $(du -sh "$TARGET_DIR/sim-universal/$BUILD_DIR/lib${LIB_NAME}.a" | cut -f1)"
echo "  xcframework:       $(du -sh "$ROOT_DIR/${FRAMEWORK_NAME}.xcframework" | cut -f1)"
echo ""
echo "  Swift Package:     $OUTPUT_PACKAGE/"
echo "  Add to Xcode:      File → Add Package Dependencies → Add Local"
echo "                     → select $OUTPUT_PACKAGE/"
echo ""
echo "  Import in Swift:   import OccultaCore"
```

---

## Workspace Layout

```
occulta-workspace/
├── Cargo.toml              [workspace]
├── occulta-protocol/
├── occulta-crypto/
├── occulta-ffi/
├── OccultaSDK/             ← generated — do not edit manually
│   ├── Package.swift
│   ├── Sources/OccultaCore/OccultaCore.swift
│   └── OccultaCoreFFI.xcframework/
└── scripts/
    └── build-xcframework.sh
```

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    "occulta-protocol",
    "occulta-crypto",
    "occulta-ffi",
]
resolver = "2"

[workspace.dependencies]
serde      = { version = "1",    features = ["derive"] }
serde_json = { version = "1" }
sha2       = "0.10"
zeroize    = { version = "1.7",  features = ["derive"] }
thiserror  = "1"
```
