//
//  AppLayerConfig+Model.swift
//  Occulta
//

import CryptoKit
import Foundation
import SwiftData

/// Routing depth — which contact layer the app is currently showing.
///
/// `.normal` (depth 0) — the real layer; all contacts visible.
/// `.duress` (depth 1) — the decoy layer; sensitive contacts filtered out.
enum RoutingDepth: Int, Codable {
    case normal = 0
    case duress = 1
}

@Model
final class AppLayerConfig {
    var sealedNormalVerifier: Data?
    var sealedDuressVerifier: Data?
    /// Encrypted `RoutingDepth`. Records which layer (real vs decoy) was active
    /// when config was last written, so `Manager.Security.init` can restore
    /// depth-filtering and `.duress` state after a process kill without
    /// re-authentication.
    ///
    /// Always non-nil after the first config write — a consistently present field
    /// prevents forensic tools from inferring the device's threat state from
    /// field presence or absence.
    ///
    /// Falls back to `.normal` on any decode failure — the safe default.
    var persistedDepth: Data?

    /// Encrypted Bool. Legacy scalar kept for migration reads in `Manager.Security.init()`.
    /// Source of truth is `pinEnabledPerDepth`. New rows leave this nil.
    var pinEnabled: Data?

    /// Per-depth PIN gate state. `pinEnabledPerDepth[N]` decrypts to `true` when the
    /// PIN overlay fires at depth N; `false` when the gate is suppressed while all
    /// verifiers remain intact — the coercion path where the user called
    /// `disablePIN(at:confirmingPIN:)` so the app opens without demanding a PIN.
    /// Depth-filtering still applies when `false`.
    ///
    /// Padded to `paddedArrayCount` entries so array length is forensically constant.
    /// Filler entries are encrypted `1` — indistinguishable from a real entry where
    /// the gate is up. Falls back to `true` per entry on any decode failure.
    ///
    /// **Encoding — UInt8, not Bool:**
    /// Each entry is JSON-encoded as `UInt8(1)` (enabled) or `UInt8(0)` (disabled),
    /// producing a single-byte payload in both cases. A `Bool` encoding would produce
    /// `"true"` (4 bytes) vs `"false"` (5 bytes); AES-GCM does not pad, so the sealed
    /// box sizes would differ by one byte. A forensic examiner could identify the
    /// disabled slot by size alone — without the SE key and without decryption.
    /// See `pinEnabledFillerArray()` for the canonical explanation.
    var pinEnabledPerDepth: [Data] = []

    /// Encrypted Int. The depth that is the "home" layer for the current operator.
    ///
    /// **Background — the coercer re-enable problem (Bugs 37, 47, 48):**
    ///
    /// When the user lowers the PIN gate under coercion at depth N and the coercer
    /// re-enables it with a PIN C that matches no existing verifier, the system creates
    /// a new layer: `sealedDuressVerifiers[N]` and `sealedNormalVerifiers[N+1]` are
    /// written for C. The coercer's PIN therefore routes them to depth N+1.
    ///
    /// From that point on, depth N+1 is the coercer's effective "depth 0". The app must
    /// present a fully functional Secure Mode experience from that depth — including the
    /// "Deactivate Protection" button after the coercer activates their own SM layer, and
    /// a working `ContactClassification` flow — otherwise observable differences from a
    /// real depth-0 session reveal that Secure Mode was already active when the device
    /// was received. This field records the coercer's home depth so those UI affordances
    /// can be selectively unlocked at the right depth.
    ///
    /// **Why 0 is the correct default (and safe fallback):**
    ///
    /// `0` means "the real user's depth is the home". Every install that has never been
    /// through a coercion re-enable has `coercerBaseDepth == 0`, so the conditions
    /// `currentDepth == 0 || currentDepth == coercerBaseDepth` simplify to
    /// `currentDepth == 0` — preserving the original behaviour exactly.
    ///
    /// On any decode failure the field falls back to 0, which is conservative: it
    /// restricts rather than opens. A coercer who loses their home depth due to a
    /// decode failure reverts to pre-fix behaviour (the two tells reappear), not to a
    /// state that exposes the real user's data.
    ///
    /// **Forensic neutrality:**
    ///
    /// Written unconditionally at first config creation (value 0) alongside `persistedDepth`
    /// and `pinEnabled`, so its presence never leaks coercion history. A field that
    /// appears only after a coercion event would itself be a forensic tell.
    var coercerBaseDepth: Data? = nil

    /// Encrypted Int. Consecutive wrong attempt count since last successful verification.
    /// nil = 0 (no wrong attempts). Reset to nil on any successful verification or activation.
    var lockoutCountEncrypted: Data? = nil

    /// Encrypted TimeInterval — `ProcessInfo.systemUptime` at the moment the current
    /// lockout wait period started (set on the wrong attempt that first triggers a
    /// delay, or re-anchored if a reboot is detected before the wait completes).
    /// nil = not currently locked out. Deliberately NOT wall-clock time — see SEC-1:
    /// a stored `Date` compared against `Date.now` is bypassable by changing the
    /// device clock. Monotonic uptime can't be changed by the user and can only
    /// decrease if the device has actually rebooted, which `verify()` detects and
    /// re-anchors rather than treating as elapsed time.
    var lockoutAnchorUptimeEncrypted: Data? = nil

    /// Encrypted slot index per depth, parallel to sealedDuressVerifiers.
    /// Index 0 = real layer (depth 0). Padded to 32 entries with random filler
    /// so the array length does not reveal how many real layers are configured.
    /// Initialised at row creation; random filler entries fail to decrypt gracefully.
    var sealedBlobSlots: [Data] = []

    /// Random UInt32 written at each activation push; validated on pop to detect stale
    /// blobs from prior activation cycles. Cleared to random filler on deactivation so
    /// no activation history persists in the DB.
    /// One value per depth, parallel to sealedBlobSlots.
    var layerSequenceNumbers: [Data] = []

    // MARK: - Verifier arrays (multi-layer)
    //
    // Both arrays are always padded to maxVerifierCount entries. Filler entries are
    // random bytes of exactly verifierFillerSize (= PINManager.verifierSize = 53 bytes),
    // indistinguishable in size from real verifiers. `verify()` simply ignores entries
    // that fail to open — filler always fails. A forensic examiner always sees exactly
    // maxVerifierCount blobs per array regardless of how many real layers are active.
    //
    // Must equal LayerStore.slotCount (32) so neither the file size nor the verifier
    // array length leaks more information than the other.

    /// `[0]` = master PIN (normalLabel). `[N]` = routing alias for `sealedDuressVerifiers[N-1]`
    /// (same PIN as duressVerifiers[N-1], built with normalLabel). Enables cold-start routing:
    /// entering any duress PIN matches the alias at index N and routes directly to depth N.
    var sealedNormalVerifiers: [Data] = []

    /// `[N]` = verifier for the duress PIN that pushes depth N → N+1 (duressLabel).
    var sealedDuressVerifiers: [Data] = []

    /// The fixed capacity of both verifier arrays. Must equal `Manager.LayerStore.slotCount`
    /// so the file and the array lengths are forensically coupled — neither reveals more.
    static let maxVerifierCount: Int = 32

    init() {
        self.sealedBlobSlots       = Self.randomFillerArray()
        self.layerSequenceNumbers  = Self.randomFillerArray()
        self.sealedNormalVerifiers = Self.verifierFillerArray()
        self.sealedDuressVerifiers = Self.verifierFillerArray()
        self.pinEnabledPerDepth    = Self.pinEnabledFillerArray()
    }

    // MARK: - Blob slot

    /// Blob metadata is sealed under a key derived from the **SE Secure Mode key**, not the
    /// local DB key — see `blobMetadataKey(from:)` for why that distinction is the whole point.
    func readBlobSlot(at depth: Int, using key: SymmetricKey) -> Int? {
        guard depth < self.sealedBlobSlots.count,
              let decrypted = self.sealedBlobSlots[depth].decrypt(using: key),
              let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeBlobSlot(_ slot: Int, at depth: Int, using key: SymmetricKey) throws {
        // encrypt() on non-nil Data should never return nil — nil only arises from the
        // encrypt(data: Data?) overload when input is nil. Treat nil as a key failure
        // and throw rather than silently skipping: a missing blob slot means deactivation
        // will never find the blob and sensitive contacts will be permanently lost.
        guard let encrypted = try JSONEncoder().encode(slot).encrypt(using: key) else {
            throw CocoaError(.coderValueNotFound)
        }
        self.ensurePadded()
        if depth < self.sealedBlobSlots.count {
            self.sealedBlobSlots[depth] = encrypted
        }
    }

    func clearBlobSlot(at depth: Int) {
        self.ensurePadded()
        
        if depth < self.sealedBlobSlots.count {
            self.sealedBlobSlots[depth] = Self.randomFiller()
        }
    }

    // MARK: - Sequence number

    func readSequenceNumber(at depth: Int, using key: SymmetricKey) -> Int? {
        guard depth < self.layerSequenceNumbers.count,
              let decrypted = self.layerSequenceNumbers[depth].decrypt(using: key),
              let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeSequenceNumber(_ seqNum: Int, at depth: Int, using key: SymmetricKey) throws {
        // Same invariant as writeBlobSlot — nil from encrypt() is a key failure, not a
        // valid code path for non-nil input. Throw so activation aborts rather than
        // succeeding silently with missing deactivation metadata.
        guard let encrypted = try JSONEncoder().encode(seqNum).encrypt(using: key) else {
            throw CocoaError(.coderValueNotFound)
        }
        self.ensurePadded()
        if depth < self.layerSequenceNumbers.count {
            self.layerSequenceNumbers[depth] = encrypted
        }
    }

    func clearSequenceNumber(at depth: Int) {
        self.ensurePadded()

        if depth < self.layerSequenceNumbers.count {
            self.layerSequenceNumbers[depth] = Self.randomFiller()
        }
    }

    /// Replaces the entire blob-slot and sequence-number arrays with fresh random filler.
    /// Use on full deactivation (depth ≤ 1) to wipe all blob metadata regardless of how
    /// many layers were activated above depth 0 — no hardcoded indices required.
    func clearAllBlobMetadata() {
        self.sealedBlobSlots      = Self.randomFillerArray()
        self.layerSequenceNumbers = Self.randomFillerArray()
    }

    // MARK: - Blob metadata key

    /// Derives the key that seals `sealedBlobSlots` and `layerSequenceNumbers`, from the SE
    /// Secure Mode key rather than the local DB key.
    ///
    /// **Why these two arrays live on a different key from everything else here.** The local DB
    /// key rotates on every activation and deactivation, and this row was never re-keyed with
    /// it — so an entry written by one activation was stranded by the next, and the blob it
    /// pointed at became unreachable forever (Bug 76). Re-keying the arrays alongside the other
    /// fields would fix that, but only for as long as the rotation code stays correct. Deriving
    /// them from a key that never rotates removes the failure mode by construction instead.
    ///
    /// **Why this costs nothing in exposure.** The blob *contents* are already sealed under
    /// `LayerStore.deriveKey(from:)`, derived from this same SE key. A slot index is strictly
    /// less sensitive than the payload it points at, and that payload is already protected by
    /// the identical root secret — so nothing becomes reachable that was not reachable before.
    ///
    /// Domain-separated with its own HKDF info string so this key is distinct from the layer
    /// store's, matching how `LayerStore.deriveKey(from:)` separates itself from the raw SE key.
    static func blobMetadataKey(from seKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: seKey,
            info: Data("blob-metadata-key".utf8),
            outputByteCount: 32
        )
    }

    /// Moves any blob-metadata entry still sealed under the local DB key onto the SE-derived
    /// key, in place. Idempotent and safe to run on every launch: once an entry opens under
    /// `blobKey` there is nothing to do, and filler opens under neither key.
    ///
    /// Needed because installs that activated Secure Mode before this change hold entries under
    /// whatever local DB key was canonical at the time. Without a migration those would be read
    /// with the SE key, fail, and be treated as absent — silently orphaning a blob that is
    /// currently perfectly reachable.
    ///
    /// Entries that open under neither key are already stranded by an earlier rotation and are
    /// left alone; nothing here can recover them.
    ///
    /// - Returns: `true` when at least one entry was moved, so the caller knows to save.
    @discardableResult
    func migrateBlobMetadata(fromLocalDBKey dbKey: SymmetricKey, toBlobKey blobKey: SymmetricKey) -> Bool {
        self.ensurePadded()
        var changed = false

        func migrate(_ array: inout [Data]) {
            for index in array.indices {
                guard array[index].decrypt(using: blobKey) == nil,
                      let plain = array[index].decrypt(using: dbKey),
                      let resealed = ((try? plain.encrypt(using: blobKey)) ?? nil)
                else { continue }
                array[index] = resealed
                changed = true
            }
        }

        migrate(&self.sealedBlobSlots)
        migrate(&self.layerSequenceNumbers)
        return changed
    }

    // MARK: - Key rotation

    /// Re-encrypts every field on this row that is sealed under the **local DB key** from
    /// `oldKey` to `newKey`. The counterpart of `Contact.Profile.reencryptAllFields(to:aad:)`
    /// and `Group.reencrypt(from:to:)`, and the reason this row survives a rotation (Bug 76).
    ///
    /// Must run while `oldKey` is still canonical, i.e. before `commitStagedLocalDBKey()`.
    ///
    /// Deliberately does **not** cover `sealedBlobSlots` or `layerSequenceNumbers`: those moved
    /// to the non-rotating SE Secure Mode key precisely so no rotation can strand them. Nor the
    /// verifier arrays, which were always sealed by `PINManager` under that same SE key — which
    /// is why PIN entry kept working across rotations even while everything here did not.
    ///
    /// `pinEnabledPerDepth` is re-sealed entry by entry rather than skipped, because its filler
    /// *is* real ciphertext (encrypted `1`, chosen so enabled and disabled encode to equal
    /// lengths — see `pinEnabledFillerArray()`). An entry that will not decrypt under `oldKey`
    /// is stranded from an earlier rotation and its value is already unrecoverable; it is
    /// re-sealed as `1`, which is exactly what `readPinEnabled(at:)` reports for it anyway. That
    /// keeps all 32 entries equal-length and mutually indistinguishable instead of leaving
    /// stranded garbage sitting among live entries.
    ///
    /// Scalars that fail to decrypt are left byte-identical rather than nil-ed. Their read
    /// accessors already document safe fallbacks (0 / true / 0 / not-locked-out), so a stranded
    /// scalar degrades to that fallback; discarding the ciphertext would gain nothing and would
    /// make a nil field stand out against rows where it is always present.
    func reencrypt(from oldKey: SymmetricKey, to newKey: SymmetricKey) throws {
        self.persistedDepth   = Self.reseal(self.persistedDepth,   from: oldKey, to: newKey)
        self.pinEnabled       = Self.reseal(self.pinEnabled,       from: oldKey, to: newKey)
        self.coercerBaseDepth = Self.reseal(self.coercerBaseDepth, from: oldKey, to: newKey)
        self.lockoutCountEncrypted        = Self.reseal(self.lockoutCountEncrypted,        from: oldKey, to: newKey)
        self.lockoutAnchorUptimeEncrypted = Self.reseal(self.lockoutAnchorUptimeEncrypted, from: oldKey, to: newKey)

        self.ensurePadded()
        let enabledFallback = try JSONEncoder().encode(UInt8(1))
        self.pinEnabledPerDepth = try self.pinEnabledPerDepth.map { entry in
            let plain = entry.decrypt(using: oldKey) ?? enabledFallback
            guard let resealed = try plain.encrypt(using: newKey) else {
                throw CocoaError(.coderValueNotFound)
            }
            return resealed
        }
    }

    /// Decrypt-and-reseal for a single optional scalar. Returns the input untouched when it is
    /// absent or will not open under `oldKey` — see `reencrypt(from:to:)` for why.
    private static func reseal(_ data: Data?, from oldKey: SymmetricKey, to newKey: SymmetricKey) -> Data? {
        guard let data, let plain = data.decrypt(using: oldKey) else { return data }
        return ((try? plain.encrypt(using: newKey)) ?? nil) ?? data
    }

    // MARK: - Verifier array helpers

    /// Writes a normal verifier at `depth`, padding the array to `maxVerifierCount` first.
    func writeNormalVerifier(_ verifier: Data, at depth: Int) {
        self.ensureVerifiersPadded()
        if depth < self.sealedNormalVerifiers.count {
            self.sealedNormalVerifiers[depth] = verifier
        }
    }

    /// Writes a duress verifier at `depth`, padding the array to `maxVerifierCount` first.
    func writeDuressVerifier(_ verifier: Data, at depth: Int) {
        self.ensureVerifiersPadded()
        if depth < self.sealedDuressVerifiers.count {
            self.sealedDuressVerifiers[depth] = verifier
        }
    }

    /// Replaces `sealedNormalVerifiers[depth]` and above with fresh random filler,
    /// removing all verifiers for layers at or deeper than `depth`.
    func clearVerifiers(from depth: Int) {
        self.ensureVerifiersPadded()
        for i in depth..<self.sealedNormalVerifiers.count {
            self.sealedNormalVerifiers[i] = Self.verifierFiller()
        }
        for i in (depth == 0 ? 0 : depth - 1)..<self.sealedDuressVerifiers.count {
            self.sealedDuressVerifiers[i] = Self.verifierFiller()
        }
    }

    // MARK: - Private

    private static let paddedArrayCount = 32  // Manager.LayerStore.slotCount
    /// Byte size of random filler for blob-slot and sequence-number arrays.
    private static let fillerSize = 30
    /// Byte size of random filler for verifier arrays — must equal PINManager.verifierSize (53).
    static let verifierFillerSize = 53

    private func ensurePadded() {
        while self.sealedBlobSlots.count < Self.paddedArrayCount {
            self.sealedBlobSlots.append(Self.randomFiller())
        }
        while self.layerSequenceNumbers.count < Self.paddedArrayCount {
            self.layerSequenceNumbers.append(Self.randomFiller())
        }
        while self.pinEnabledPerDepth.count < Self.paddedArrayCount {
            self.pinEnabledPerDepth.append((try? JSONEncoder().encode(UInt8(1)).encrypt()) ?? Self.randomFiller())
        }
    }

    private func ensureVerifiersPadded() {
        while self.sealedNormalVerifiers.count < Self.maxVerifierCount {
            self.sealedNormalVerifiers.append(Self.verifierFiller())
        }
        while self.sealedDuressVerifiers.count < Self.maxVerifierCount {
            self.sealedDuressVerifiers.append(Self.verifierFiller())
        }
    }

    private static func randomFiller() -> Data {
        // SystemRandomNumberGenerator uses arc4random_buf under the hood, seeded by the
        // kernel at boot — always available on any running iOS device. Unlike SecRandomCopyBytes
        // it has no error return, so no throws cascade into non-throwing call sites.
        var rng = SystemRandomNumberGenerator()
        return Data((0..<fillerSize).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }

    static func verifierFiller() -> Data {
        var rng = SystemRandomNumberGenerator()
        return Data((0..<verifierFillerSize).map { _ in UInt8.random(in: 0...255, using: &rng) })
    }

    static func randomFillerArray() -> [Data] {
        (0..<paddedArrayCount).map { _ in Self.randomFiller() }
    }

    static func verifierFillerArray() -> [Data] {
        (0..<maxVerifierCount).map { _ in Self.verifierFiller() }
    }

    /// Returns a 32-entry array of encrypted `1` values — the default for a fresh install
    /// or any depth that has never had the gate explicitly disabled. All entries are encrypted
    /// so they are indistinguishable from a real entry where the gate is up.
    ///
    /// Encoded as `UInt8` (not `Bool`) so `enabled=true` and `enabled=false` produce
    /// equal-length JSON (`"1"` vs `"0"`, both 1 byte). AES-GCM does not pad, so a
    /// Bool encoding would leak the value through ciphertext length alone — `"true"` (4 bytes)
    /// vs `"false"` (5 bytes) would differ by one byte without any decryption.
    static func pinEnabledFillerArray() -> [Data] {
        (0..<paddedArrayCount).map { _ in
            (try? JSONEncoder().encode(UInt8(1)).encrypt()) ?? randomFiller()
        }
    }


    // MARK: - Routing depth

    /// Decodes the persisted routing depth as a raw integer.
    ///
    /// Storing an `Int` (rather than the two-case `RoutingDepth` enum) lets callers
    /// round-trip the full `currentDepth` value — including depths > 1 that arise in
    /// multi-layer coercion stacks. On-disk encoding is unchanged: existing rows
    /// store 0 or 1 as JSON integers, which decode correctly as `Int`.
    ///
    /// Falls back to `0` (`.normal`) on any decode failure — the safe default.
    func readPersistedDepth() -> Int {
        guard
            let data      = self.persistedDepth,
            let decrypted = data.decrypt(),
            let value     = DepthCodec.decode(decrypted)
        else { return 0 }
        return value
    }

    func writePersistedDepth(_ depth: Int) throws {
        self.persistedDepth = try DepthCodec.encode(depth).encrypt()
    }

    // MARK: - PIN enabled (per depth)

    /// Decodes the gate state for `depth`. Falls back to `true` (PIN required) on any decode failure.
    ///
    /// Encoded as `UInt8` (0/1) — see `pinEnabledFillerArray()` for the length-leak rationale.
    func readPinEnabled(at depth: Int) -> Bool {
        guard depth < self.pinEnabledPerDepth.count,
              let decrypted = self.pinEnabledPerDepth[depth].decrypt(),
              let value     = try? JSONDecoder().decode(UInt8.self, from: decrypted)
        else { return true }
        return value != 0
    }

    /// - Note: Encoded as `UInt8` — see `pinEnabledPerDepth` field docs for the length-leak rationale.
    func writePinEnabled(_ enabled: Bool, at depth: Int) throws {
        guard let encrypted = try JSONEncoder().encode(enabled ? UInt8(1) : UInt8(0)).encrypt() else {
            throw CocoaError(.coderValueNotFound)
        }
        self.ensurePadded()
        if depth < self.pinEnabledPerDepth.count {
            self.pinEnabledPerDepth[depth] = encrypted
        }
    }

    /// Legacy scalar read — used only during migration in `Manager.Security.init()`.
    /// After migration, `readPinEnabled(at:)` is the sole source of truth.
    func readPinEnabledLegacy() -> Bool {
        guard let data      = self.pinEnabled,
              let decrypted = data.decrypt(),
              let value     = try? JSONDecoder().decode(Bool.self, from: decrypted)
        else { return true }
        return value
    }

    // MARK: - Coercer base depth

    /// Decodes the coercer's home depth. Falls back to 0 on any decode failure.
    ///
    /// 0 is the real user's depth and the correct default for all installs that have
    /// never been through a coercion re-enable. See `coercerBaseDepth` field docs.
    func readCoercerBaseDepth() -> Int {
        guard
            let data      = self.coercerBaseDepth,
            let decrypted = data.decrypt(),
            let value     = DepthCodec.decode(decrypted)
        else { return 0 }
        return value
    }

    func writeCoercerBaseDepth(_ depth: Int) throws {
        self.coercerBaseDepth = try DepthCodec.encode(depth).encrypt()
    }

    // MARK: - Lockout counter

    func readLockoutCount() -> Int {
        guard let data      = self.lockoutCountEncrypted,
              let decrypted = data.decrypt(),
              let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return 0 }
        return value
    }

    func writeLockoutCount(_ count: Int) throws {
        self.lockoutCountEncrypted = try JSONEncoder().encode(count).encrypt()
    }

    func readLockoutAnchorUptime() -> TimeInterval? {
        guard let data      = self.lockoutAnchorUptimeEncrypted,
              let decrypted = data.decrypt(),
              let value     = try? JSONDecoder().decode(TimeInterval.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeLockoutAnchorUptime(_ uptime: TimeInterval) throws {
        self.lockoutAnchorUptimeEncrypted = try JSONEncoder().encode(uptime).encrypt()
    }

    func resetLockout() {
        self.lockoutCountEncrypted        = nil
        self.lockoutAnchorUptimeEncrypted = nil
    }
}
