//
//  AppLayerConfig+Model.swift
//  Occulta
//

import Foundation
import SwiftData
import Security

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
    /// Filler entries are encrypted `true` — indistinguishable from a real entry where
    /// the gate is up. Falls back to `true` per entry on any decode failure.
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

    /// Encrypted Date. When the current lockout expires; nil = not currently locked out.
    var lockoutExpiryEncrypted: Data? = nil

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

    func readBlobSlot(at depth: Int) -> Int? {
        guard depth < self.sealedBlobSlots.count,
              let decrypted = self.sealedBlobSlots[depth].decrypt(),
              let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeBlobSlot(_ slot: Int, at depth: Int) throws {
        // encrypt() on non-nil Data should never return nil — nil only arises from the
        // encrypt(data: Data?) overload when input is nil. Treat nil as a key failure
        // and throw rather than silently skipping: a missing blob slot means deactivation
        // will never find the blob and sensitive contacts will be permanently lost.
        guard let encrypted = try JSONEncoder().encode(slot).encrypt() else {
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

    func readSequenceNumber(at depth: Int) -> Int? {
        guard depth < self.layerSequenceNumbers.count,
              let decrypted = self.layerSequenceNumbers[depth].decrypt(),
              let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeSequenceNumber(_ seqNum: Int, at depth: Int) throws {
        // Same invariant as writeBlobSlot — nil from encrypt() is a key failure, not a
        // valid code path for non-nil input. Throw so activation aborts rather than
        // succeeding silently with missing deactivation metadata.
        guard let encrypted = try JSONEncoder().encode(seqNum).encrypt() else {
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
            self.pinEnabledPerDepth.append((try? JSONEncoder().encode(true).encrypt()) ?? Self.randomFiller())
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
        var data = Data(count: fillerSize)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, fillerSize, $0.baseAddress!)
        }
        return data
    }

    static func verifierFiller() -> Data {
        var data = Data(count: verifierFillerSize)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, verifierFillerSize, $0.baseAddress!)
        }
        return data
    }

    static func randomFillerArray() -> [Data] {
        (0..<paddedArrayCount).map { _ in Self.randomFiller() }
    }

    static func verifierFillerArray() -> [Data] {
        (0..<maxVerifierCount).map { _ in Self.verifierFiller() }
    }

    /// Returns a 32-entry array of encrypted `true` values — the default for a fresh install
    /// or any depth that has never had the gate explicitly disabled. All entries are encrypted
    /// so they are indistinguishable from a real entry where the gate is up.
    static func pinEnabledFillerArray() -> [Data] {
        (0..<paddedArrayCount).map { _ in
            (try? JSONEncoder().encode(true).encrypt()) ?? randomFiller()
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
            let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return 0 }
        return value
    }

    func writePersistedDepth(_ depth: Int) throws {
        self.persistedDepth = try JSONEncoder().encode(depth).encrypt()
    }

    // MARK: - PIN enabled (per depth)

    /// Decodes the gate state for `depth`. Falls back to `true` (PIN required) on any decode failure.
    func readPinEnabled(at depth: Int) -> Bool {
        guard depth < self.pinEnabledPerDepth.count,
              let decrypted = self.pinEnabledPerDepth[depth].decrypt(),
              let value     = try? JSONDecoder().decode(Bool.self, from: decrypted)
        else { return true }
        return value
    }

    func writePinEnabled(_ enabled: Bool, at depth: Int) throws {
        guard let encrypted = try JSONEncoder().encode(enabled).encrypt() else {
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
            let value     = try? JSONDecoder().decode(Int.self, from: decrypted)
        else { return 0 }
        return value
    }

    func writeCoercerBaseDepth(_ depth: Int) throws {
        self.coercerBaseDepth = try JSONEncoder().encode(depth).encrypt()
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

    func readLockoutExpiry() -> Date? {
        guard let data      = self.lockoutExpiryEncrypted,
              let decrypted = data.decrypt(),
              let value     = try? JSONDecoder().decode(Date.self, from: decrypted)
        else { return nil }
        return value
    }

    func writeLockoutExpiry(_ date: Date) throws {
        self.lockoutExpiryEncrypted = try JSONEncoder().encode(date).encrypt()
    }

    func resetLockout() {
        self.lockoutCountEncrypted  = nil
        self.lockoutExpiryEncrypted = nil
    }
}
