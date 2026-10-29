//
//  KeyReseal+Verifiers.swift
//  Occulta
//
//  The PIN verifier wrap of Bug 171, Stage 3 (`Docs/Features/Secure Mode/bugs.md`). A verifier is
//  `AES-GCM(HKDF(deriveSecureModeKey(), label ‖ pin), sentinel)`, 53 bytes, and `deriveSecureModeKey()` is a function
//  of the PIN Enclave key's public point. So anyone holding that point and the config row can test a PIN guess offline
//  against 64 verifiers, with no Enclave and no lockout counter. The wrap seals each verifier again under
//  `enclaveBoundKey(.secureModeWrap)`, which needs `r_U` and the tier U record: 53 -> 81 bytes, no AAD, as the inner
//  verifier has none. The inner layer is exactly what it was.
//
//  Wrapped or not is decided by size alone: 53 bytes is plain, 81 is wrapped. The pass runs in the launch sequence after
//  the tier U reseal and before `Manager.Security`, in one transaction on the config row, and it changes every value in
//  it together, filler included: a run that wrapped only the slots that hold a real verifier would show, in a diff,
//  which ones those are. Afterwards the launch sequence tells the process to write wrapped verifiers if every one in
//  the store is (`Manager.Ambient.pinVerifiers`), so an array is never mixed.
//
//  `OccultaTests/SecureMode/PINVerifierWrapTests.swift` was written against a stub of this first (Stage 3a).
//

import Foundation
import SwiftData
import CryptoKit

extension KeyReseal {

    nonisolated enum VerifierAbort: Equatable {
        /// There is no `AppLayerConfig` row to wrap.
        case configMissing
        /// `enclaveBoundKey(.secureModeWrap)` can't be derived: no Enclave, no `r_U`, no record that decapsulates.
        case wrapKeyUnavailable
    }

    nonisolated enum VerifierOutcome: Equatable {
        /// The pass didn't run.
        case notRun
        /// Every verifier was sealed under the wrap key and committed in one transaction.
        case wrapped
        /// No verifier was 53 bytes, so nothing was read or written.
        case alreadyDone
        /// A new ciphertext didn't read back: nothing was written.
        case incomplete
        /// Nothing was written.
        case aborted(VerifierAbort)
    }

    nonisolated struct VerifierReport: Equatable {
        var outcome = VerifierOutcome.notRun
        /// 53-byte verifiers (and filler) sealed under the wrap key.
        var wrapped = 0
        /// 81-byte values that already opened under the wrap key, sealed again with a fresh nonce so that the row changes whole.
        var rewritten = 0
        /// 81-byte values that open under no key: random filler, replaced by fresh random bytes of the same length.
        var refreshed = 0
        /// Values of another size, left as they are.
        var left = 0
        /// New ciphertexts that didn't read back.
        var failed = 0
    }

    private struct VerifierAborted: Error {
        let reason: VerifierAbort
    }

    /// Where a verifier lives in the config row.
    private enum Place {
        case normalScalar
        case duressScalar
        case normal(Int)
        case duress(Int)
    }

    /// Seals every PIN verifier under the wrap key, in one transaction on the config row.
    ///
    /// - A 53-byte value (a verifier, or the random filler of an unused slot) is sealed under the wrap key.
    /// - An 81-byte value that opens under it is sealed again with a fresh nonce, and one that doesn't (random filler
    ///   a wrapped process wrote) is replaced by fresh random bytes, so that the row changes whole whenever any value
    ///   in it was still plain. That happens on a re-upgrade, when the previous release has written a 53-byte
    ///   verifier into a wrapped store.
    /// - Each new ciphertext is opened and compared before anything is assigned. One that doesn't read back means no
    ///   writes at all (`.incomplete`).
    /// - A wrap key that can't be derived means no writes either (`.aborted`); nothing is created.
    /// - Nothing is read or written if no value is 53 bytes (`.alreadyDone`).
    ///
    /// Throws what an interruption looks like (`InjectedWrapFault` in a test, a SwiftData error from the `save()`); the
    /// row is then rolled back, so a kill or a failed save leaves every verifier as it was and the next launch tries again.
    @discardableResult
    static func wrapVerifiers(
        context: ModelContext, keyManager: any KeyManagerProtocol, locations: Locations = .production
    ) throws -> VerifierReport {
        var report = VerifierReport()

        do {
            try Self.performWrap(context: context, keyManager: keyManager, locations: locations, report: &report)
        } catch let aborted as VerifierAborted {
            context.rollback()
            report = VerifierReport(outcome: .aborted(aborted.reason))
        } catch {
            context.rollback()
            throw error
        }
        return report
    }

    private static func performWrap(
        context: ModelContext, keyManager: any KeyManagerProtocol, locations: Locations, report: inout VerifierReport
    ) throws {
        guard let config = try context.fetch(FetchDescriptor<AppLayerConfig>()).first else {
            throw VerifierAborted(reason: .configMissing)
        }

        // Every value the row holds, in a fixed order.
        var places: [Place] = []
        if config.sealedNormalVerifier != nil { places.append(.normalScalar) }
        if config.sealedDuressVerifier != nil { places.append(.duressScalar) }
        places += config.sealedNormalVerifiers.indices.map { Place.normal($0) }
        places += config.sealedDuressVerifiers.indices.map { Place.duress($0) }

        func value(at place: Place) -> Data {
            switch place {
            case .normalScalar:      return config.sealedNormalVerifier ?? Data()
            case .duressScalar:      return config.sealedDuressVerifier ?? Data()
            case .normal(let index): return config.sealedNormalVerifiers[index]
            case .duress(let index): return config.sealedDuressVerifiers[index]
            }
        }

        let plainSize   = Manager.PINManager.plainVerifierSize
        let wrappedSize = Manager.PINManager.wrappedVerifierSize

        guard places.contains(where: { value(at: $0).count == plainSize }) else {
            report.outcome = .alreadyDone
            return
        }

        guard let wrapKey = try? keyManager.enclaveBoundKey(.secureModeWrap) else {
            throw VerifierAborted(reason: .wrapKeyUnavailable)
        }

        func open(_ sealed: Data) -> Data? {
            guard let box = try? AES.GCM.SealedBox(combined: sealed) else { return nil }
            return try? AES.GCM.open(box, using: wrapKey)
        }

        /// `plain` sealed under the wrap key, opened and compared before it is returned; nil if it doesn't read back.
        func sealed(_ plain: Data) -> Data? {
            guard var fresh = try? AES.GCM.seal(plain, using: wrapKey, nonce: AES.GCM.Nonce()).combined else { return nil }
            #if DEBUG
            fresh = Self.faults?.corrupted(fresh) ?? fresh
            #endif
            return open(fresh) == plain ? fresh : nil
        }

        // Everything is worked out first and assigned only if all of it read back.
        var replacements: [(place: Place, bytes: Data)] = []
        var tally = VerifierReport()
        for (index, place) in places.enumerated() {
            let current = value(at: place)

            switch current.count {
            case plainSize:
                if let fresh = sealed(current) { replacements.append((place, fresh)); tally.wrapped += 1 } else { tally.failed += 1 }
            case wrappedSize:
                if let inner = open(current) {
                    if let fresh = sealed(inner) { replacements.append((place, fresh)); tally.rewritten += 1 } else { tally.failed += 1 }
                } else {
                    var bytes = [UInt8](repeating: 0, count: wrappedSize)
                    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
                    replacements.append((place, Data(bytes)))
                    tally.refreshed += 1
                }
            default:
                tally.left += 1
            }

            #if DEBUG
            if index == 0 { try Self.faults?.reachWrap(.afterFirstValue) }
            if index == places.count / 2 { try Self.faults?.reachWrap(.midWrap) }
            #endif
        }

        guard tally.failed == 0 else {
            report = VerifierReport(outcome: .incomplete, failed: tally.failed)
            return
        }

        var normals  = config.sealedNormalVerifiers
        var duresses = config.sealedDuressVerifiers
        for (place, bytes) in replacements {
            switch place {
            case .normalScalar:      config.sealedNormalVerifier = bytes
            case .duressScalar:      config.sealedDuressVerifier = bytes
            case .normal(let index): normals[index] = bytes
            case .duress(let index): duresses[index] = bytes
            }
        }
        config.sealedNormalVerifiers = normals
        config.sealedDuressVerifiers = duresses

        #if DEBUG
        try Self.faults?.reachWrap(.beforeSave)
        #endif

        try context.save()
        if let store = locations.store { OccultaApp.walCheckpoint(at: store) }

        tally.outcome = .wrapped
        report = tally
    }

    /// Whether every PIN verifier in `context`'s store is wrapped (81 bytes): the launch sequence tells the process to
    /// write wrapped verifiers by this, and by size alone. A store with no verifier at all is not (an install old enough
    /// to have empty arrays and no PIN gets plain filler from `Manager.Security`, and the next launch wraps it).
    static func verifiersAreWrapped(in context: ModelContext) -> Bool {
        guard let config = (try? context.fetch(FetchDescriptor<AppLayerConfig>()).first) ?? nil else { return false }

        let values = [config.sealedNormalVerifier, config.sealedDuressVerifier].compactMap { $0 }
            + config.sealedNormalVerifiers + config.sealedDuressVerifiers
        return !values.isEmpty && values.allSatisfy { $0.count == Manager.PINManager.wrappedVerifierSize }
    }
}
