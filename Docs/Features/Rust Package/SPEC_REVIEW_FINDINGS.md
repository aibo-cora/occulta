# Rust Package Spec — Review Findings

**Date:** 2026-06-10
**Reviewed:** `RUST_PACKAGES_SPEC.md` (May 2026) against the Swift codebase at `release/v1.8.1`
**Trigger:** Android port kickoff — the spec becomes the shared-core contract for both platforms.

Every finding below is either **✅ fixed in the spec revision** (same date), **⚠️ a decision
recorded in the spec**, or **➡️ a follow-up outside the spec**. Evidence cites the Swift
source that was checked — none of the critical findings are speculative.

---

## A. Wire-format compatibility (critical — would break Swift ⇄ Rust interop)

### F1. `Mode` enum is missing two shipped cases — ✅ fixed
The spec defined only `ForwardSecret` and `LongTermFallback`. Swift ships **four** modes:
`forwardSecret`, `forwardSecretNoPQ`, `longTermFallback`, `longTermNoPQ`
(`Occulta/Features/Forward+Secrecy/OccultaBundle.swift:117-145`). The NoPQ variants are the
classical-only paths used whenever the peer's ML-KEM material is absent or corrupt. Rust as
specified would decode every classical-only bundle as `Unsupported` and abort.
**Fix:** all four variants added with exact raw strings.

### F2. `prekeyID: nil` serialises as `null` in Rust but is omitted by Swift — ✅ fixed
Swift's synthesised Codable omits nil optionals (`encodeIfPresent`). The spec's
`SecrecyContext` had no `skip_serializing_if`, so serde would emit `"prekeyID":null`.
Fallback bundles always carry `prekeyID: nil`
(`Crypto+Manager+ForwardSecrecy.swift:145`), so **every** `longTermFallback` /
`longTermNoPQ` bundle would fail AAD authentication.
**Fix:** `#[serde(skip_serializing_if = "Option::is_none", default)]` on every `Option`
field in every wire type; recorded as new cross-cutting invariant 10.

### F3. Foundation escapes `/` as `\/`; serde_json does not — ✅ fixed
The AAD encoder is `JSONEncoder` with only `.sortedKeys` set
(`OccultaBundle.swift:422-427`) — Foundation's default escapes forward slashes. The AAD
contains base64 (`ephemeralPublicKey`), whose alphabet includes `/`, so most real AADs are
affected and would fail authentication **non-deterministically** (only when the key bytes
happen to base64-encode with a slash).
**Fix:** `to_foundation_json()` helper specified in `bundle.rs` (byte-level `/` → `\/`
substitution — safe because `/` has no structural meaning in serde_json output);
`compute_aad` routed through it; dedicated test vector added.

### F4. `Version` enum lacks the `unsupported` decode fallback — ✅ fixed
Swift's `Version.init(from:)` maps unknown raw strings to `.unsupported` and surfaces
"requires a newer version of Occulta" (`OccultaBundle.swift:91-106`). The spec's Rust enum
had no `#[serde(other)]` variant, so an unknown version would be a hard `DecodingError` —
killing the whole bundle decode instead of the graceful path.
**Fix:** `Unsupported` variant added with `#[serde(other)]`; `raw_bytes()` now returns
`Option` so AAD computation aborts on it (matching Swift, which throws before AAD).

### F5. `ShardOperation` wire shape is wrong — ✅ fixed
Two errors (`OccultaBundle.swift:215-219`):
- `attribute` is a nested `SignedAttribute` **JSON object** in Swift
  (`Occulta/Features/Vault/SignedAttribute.swift`), not base64 `Data` as the spec modelled.
- The JSON key is `attributeID` (capital ID); `rename_all = "camelCase"` produces
  `attributeId` — the same casing trap the spec itself flagged for `prekeyID`.

**Fix:** explicit `rename = "attributeID"`; `attribute` retyped as
`Option<SignedAttribute>` with a note that the full `SignedAttribute` Codable shape must be
mirrored from Swift at scaffold time.

### F6. "Bundle encode must be byte-equivalent to Swift" is a false requirement — ✅ fixed
Swift's own `encoded()` uses a default `JSONEncoder` (`OccultaBundle.swift:395-397`) whose
key order is non-deterministic — Swift cannot meet this requirement itself. Only the AAD is
byte-exact. Chasing byte-equality on the full bundle would have wasted effort and implied
the wrong design constraints.
**Fix:** requirement relaxed to round-trip compatibility; AAD remains the only byte-exact
artifact.

### F7. FFI `bundle_compute_aad` accepted pre-serialised `SecrecyContext` JSON — ✅ fixed
The UDL signature was `bundle_compute_aad(bytes version_raw_utf8, bytes secrecy_json)` —
leaving JSON canonicalisation (sorted keys, nil omission, slash escaping) **on each
platform**. Kotlin would have had to reproduce Foundation's encoder. That defeats the
purpose of a shared core.
**Fix:** the FFI now takes structured fields (`version_raw`, `mode_raw`,
`ephemeral_public_key`, `prekey_id?`) and Rust performs the canonical serialisation in
exactly one place for both platforms.

---

## B. Android enablement (the reason for this project — absent from the spec)

### F8. ECDH output mismatch: SE applies X9.63 KDF, Android Keystore does not — ⚠️ decision recorded
Invariant 1 assumed Rust always receives the output of `SecKeyCopyKeyExchangeResult` with
`.ecdhKeyExchangeCofactorX963SHA256` — the SE applies the ANSI X9.63 KDF in hardware. Every
Swift call site passes `requestedSize: 32` and **no SharedInfo**
(`Protocols/KeyManagerProtocol.swift`, 8 call sites), so the SE output is a single SHA-256
block: `SHA256(Z ∥ 0x00000001)`. Android Keystore's `KeyAgreement` returns the **raw** ECDH
x-coordinate `Z`.
**Decision:** new `occulta-crypto/x963.rs` with `x963_kdf_sha256()` reproduces the SE step
on Android. Invariant 1 reworded: private keys still never enter Rust on either platform;
the raw shared secret enters Rust transiently on Android only, inside this function, and is
zeroized. Interop gate: byte-match against `SecKeyCopyKeyExchangeResult` for a known key
pair.

### F9. ML-KEM-1024 has no Android home — ⚠️ decision recorded
iOS uses `SecureEnclave.MLKEM1024` (CryptoKit, iOS 26+, gated in
`Features/PostQuantum/PQProvider.swift`) — the decapsulation key never leaves the SE.
Android has no platform or hardware ML-KEM.
**Decision:** new feature-gated `occulta-crypto/mlkem.rs` backed by `libcrux-ml-kem`
(formally verified, FIPS 203 final — wire-compatible with CryptoKit). **Documented posture
difference:** the Android decapsulation key is software-held (Zeroizing in memory,
encrypted at rest under the hybrid local-DB key). Accepted because the classical ECDH half
of every hybrid derivation remains hardware-backed, so ML-KEM key compromise alone never
breaks a session key. Must appear in audit notes.

### F10. No hardware-key-storage policy for Android — ⚠️ decision recorded
`has_secure_key_storage()` semantics were iOS-only. StrongBox is the SE-equivalent, but
StrongBox ECDH is unsupported on most devices.
**Decision (new "Android Platform Policy" section):** minSdk 31 (Keystore ECDH requires API
31); keys must be hardware-backed (TEE **or** StrongBox, prefer StrongBox per-key where the
operation is supported); never software keys — a device that cannot do hardware ECDH cannot
run Occulta.

### F11. No Android build path — ✅ fixed
The spec produced only an `.xcframework`. Added: `scripts/build-android.sh` outline
(`cargo-ndk` for `arm64-v8a` + `x86_64`, `uniffi-bindgen --language kotlin`, Gradle AAR
module, JNA dependency note) and `android/occulta-core/` in the workspace layout.

### F12. UWB coverage on Android — ➡️ app-level, tracked
`androidx.core.uwb` covers far fewer devices than iPhone U1/U2. The Android exchange flow
needs a BLE-only fallback. Outside the Rust package; recorded in the spec's Android section
so it isn't lost.

---

## C. Tooling and build script

### F13. UDL and proc-macros defined the same functions twice — ✅ fixed
The spec shipped a full `.udl` **and** `#[uniffi::export]` wrappers for the same API —
duplicate scaffolding. **Fix:** proc-macros only; UDL and `build.rs` removed; the API
surface section rewritten as Rust signatures.

### F14. `cargo install uniffi-bindgen` is unsupported — ✅ fixed
Standalone bindgen install has been unsupported since UniFFI 0.23 (version must exactly
match the crate). **Fix:** workspace `uniffi-bindgen` bin target
(`uniffi = { features = ["cli"] }`), invoked via `cargo run -p occulta-ffi --bin
uniffi-bindgen`.

### F15. Generated binding filenames would not match the script's checks — ✅ fixed
With namespace `occulta_ffi`, UniFFI emits `occulta_ffi.swift` / `occulta_ffiFFI.h`; the
script asserted `OccultaCore.swift` / `OccultaCoreFFI.h` and would abort.
**Fix:** `occulta-ffi/uniffi.toml` with `module_name = "OccultaCore"`,
`ffi_module_name = "OccultaCoreFFI"`, and the Kotlin package name.

### F16. `TARGET_DIR` pointed at the crate, not the workspace — ✅ fixed
`TARGET_DIR="$CRATE_DIR/target"` — Cargo workspaces share one target directory at the
workspace root, so every artifact path in the script was wrong.
**Fix:** `TARGET_DIR="$ROOT_DIR/target"`.

### F17. Stale/incorrect dependency pins — ✅ fixed
`uniffi 0.27` with a pointless `tokio` feature (nothing is async) → bumped to 0.29,
feature removed. `secrecy 0.8` kept deliberately with a comment (0.10 renames `Secret` →
`SecretBox`; migrate deliberately, not incidentally). `libcrux-ml-kem` to be pinned at
scaffold time.

### F18. `Package.swift` targeted iOS 17; the project minimum is iOS 16 — ✅ fixed

---

## D. Spec-internal minor

### F19. Invariant 2 said `thread_rng()`; the code uses `OsRng` — ✅ fixed (kept `OsRng`)

### F20. `ProtocolError` listed under `secrecy.rs` but defined in `bundle.rs` — ✅ fixed (module listing corrected)

### F21. Unused `share_idx` in `gf_split` — ✅ fixed

### F22. UniFFI buffers are not zeroized — ⚠️ documented as accepted residual risk
Key material crosses the FFI as plain `Vec<u8>` copies in `RustBuffer`s (freed, not
zeroized); Swift `Data` / Kotlin `ByteArray` on the far side are likewise not zeroized.
Equivalent in practice to CryptoKit `SymmetricKey` exposure. Now stated explicitly in the
FFI section so it lands in the audit notes rather than surfacing as an audit surprise.

---

## E. Swift-side follow-ups (not spec changes)

### F23. Stale doc comment in Swift — ✅ fixed (2026-06-10)
`OccultaBundle.swift:330` said `.longTermFallback` carries the "sender's long-term identity
public key" in `ephemeralPublicKey`. The code sends empty `Data()`
(`Crypto+Manager+ForwardSecrecy.swift:145`) — which is also the correct privacy behaviour
the spec mandates. The comment would have misled the Android implementation; it now states
the empty-`Data()` rule and the privacy rationale.

### F24. Extract interop vectors from Swift tests **before any Rust code** — ➡️ first task of the new project
The three AAD vectors (non-nil `prekeyID`; nil `prekeyID`; base64 containing `/`) encode
the three known Foundation/serde divergences (F2, F3) and would have caught them. Vector
extraction is the acceptance gate for scaffolding, per the spec's migration order.
