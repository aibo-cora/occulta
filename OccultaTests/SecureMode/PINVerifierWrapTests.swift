//
//  PINVerifierWrapTests.swift
//  OccultaTests
//
//  Bug 171, Stage 3: the PIN verifiers, wrapped. Every one of the 64 verifier slots and both scalars goes from
//  `AES-GCM(HKDF(innerKey, label ‖ pin), sentinel)`, 53 bytes, to that sealed again under `enclaveBoundKey(.secureModeWrap)`,
//  81 bytes, with no AAD as the inner verifier has none. The inner layer is what it was. Whether the process writes
//  wrapped verifiers is decided once, by the launch sequence, from the sizes in the store (`Manager.Ambient.pinVerifiers`),
//  so an array is never mixed; checking accepts both sizes.
//
//  Written first (Stage 3a), against a stub that does nothing, and failing for the right reason: no slot is 81 bytes.
//
//  Frozen: the fixtures are sealed with pinned key bytes and an inline copy of the previous release's builder
//  (`FrozenPIN`), not through `PINManager`, so an edit to that code can't make a test agree with itself. Everything runs
//  without an Enclave, on `TestKeyManager.frozen()`, in both forms the device can be in.
//
//    - `PINVerifierFormatTests`:  `PINManager`, build and check, both sizes.
//    - `PINVerifierWrapPassTests`: the pass: what it writes, crash safety, read-back, failures.
//    - `PINVerifierLaunchTests`:  the launch sequence and `Manager.Security` over wrapped stores.
//

import Testing
import CryptoKit
import Foundation
import SwiftData

@testable import Occulta

// MARK: - The pins

extension Frozen {
    /// `deriveSecureModeKey()` of the frozen manager: the inner key, a function of the PIN Enclave key's public point.
    static let pinInnerKey = "38063deb73712b352819998e54fd72679683d53ecd08f3bf37505db1d7363326"
    static let pinWrapClassical = "2fa58d1cdac3e6caf076a9add7f775a6d187d06d8c6d402f61a62f424387e9d6"
    static let pinWrapHybrid = "8f06ac48c1b9a95557cddd2ae8492a0cf0a75a72c2a247f693b814262a6f9119"

    static func pinWrapKey(_ form: KeyForm) -> SymmetricKey {
        SymmetricKey(data: dataFromHex(form == .hybrid ? Self.pinWrapHybrid : Self.pinWrapClassical))
    }
}

/// The previous release's verifier, written out here: the sentinel sealed under `HKDF(innerKey, label ‖ pin)`.
enum FrozenPIN {
    static let sentinel = Data("SECURE_MODE_VERIFIED_2026".utf8)
    static let normalLabel = Data("secure-mode-normal-pin-2026".utf8)
    static let duressLabel = Data("secure-mode-duress-pin-2026".utf8)
    static let innerKey = SymmetricKey(data: dataFromHex(Frozen.pinInnerKey))

    static func pinKey(_ pin: String, label: Data, inner: SymmetricKey = FrozenPIN.innerKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: inner, info: label + Data(pin.utf8), outputByteCount: 32)
    }

    /// 53 bytes.
    static func plain(_ pin: String, label: Data, inner: SymmetricKey = FrozenPIN.innerKey) -> Data {
        try! AES.GCM.seal(Self.sentinel, using: Self.pinKey(pin, label: label, inner: inner), nonce: AES.GCM.Nonce()).combined!
    }

    /// 81 bytes: `plain` sealed under `wrapKey`, no AAD.
    static func wrapped(_ plain: Data, form: KeyForm) -> Data {
        try! AES.GCM.seal(plain, using: Frozen.pinWrapKey(form), nonce: AES.GCM.Nonce()).combined!
    }

    /// Whether `bytes` is, as they stand, a verifier of `pin` under `label`: what a holder of the inner key can test.
    static func opensAsPlain(_ bytes: Data, pin: String, label: Data) -> Bool {
        guard let box = try? AES.GCM.SealedBox(combined: bytes),
              let plaintext = try? AES.GCM.open(box, using: Self.pinKey(pin, label: label))
        else { return false }
        return plaintext == Self.sentinel
    }

    /// `bytes` opened under the wrap key of `form`, or nil.
    static func unwrapped(_ bytes: Data, form: KeyForm) -> Data? {
        Sealing.open(bytes, key: Frozen.pinWrapKey(form), aad: nil)
    }
}

// MARK: - The store

/// A store of PINs as the release before Stage 3 left it: four depths, the master PIN at depth 0 and one duress PIN
/// for each depth after it, every verifier 53 bytes.
@MainActor
final class VerifierStore {

    /// `pins[d]` is the PIN that routes to depth `d`: the master PIN, then the duress PIN of each layer.
    static let pins = ["111111", "222222", "333333", "444444"]

    let container: ModelContainer
    let keys: TestKeyManager

    /// - Parameters:
    ///   - seeded: Whether to write the four depths. False leaves the store empty, as a fresh install is.
    ///   - aliases: Whether each duress PIN also has its routing alias in the normal array. Without them a duress PIN is
    ///     found only by scanning the duress array.
    init(keys: TestKeyManager, seeded: Bool = true, aliases: Bool = true) throws {
        let schema = OccultaApp.schema
        self.container = try ModelContainer(for: schema, configurations: ModelConfiguration(schema: schema, isStoredInMemoryOnly: true))
        self.keys = keys
        if seeded { try self.seedPlain(aliases: aliases) }
    }

    private func seedPlain(aliases: Bool) throws {
        let context = ModelContext(self.container)
        let config  = AppLayerConfig()
        context.insert(config)

        var normals  = AppLayerConfig.verifierFillerArray()
        var duresses = AppLayerConfig.verifierFillerArray()
        normals[0] = FrozenPIN.plain(Self.pins[0], label: FrozenPIN.normalLabel)
        for depth in 0..<3 {
            duresses[depth] = FrozenPIN.plain(Self.pins[depth + 1], label: FrozenPIN.duressLabel)
            if aliases { normals[depth + 1] = FrozenPIN.plain(Self.pins[depth + 1], label: FrozenPIN.normalLabel) }
        }
        config.sealedNormalVerifiers = normals
        config.sealedDuressVerifiers = duresses
        config.sealedNormalVerifier  = normals[0]
        config.sealedDuressVerifier  = duresses[0]
        try config.writePersistedDepth(0)
        try context.save()
    }

    func newContext() -> ModelContext {
        let context = ModelContext(self.container)
        context.autosaveEnabled = false
        return context
    }

    func config() -> AppLayerConfig? {
        try? self.newContext().fetch(FetchDescriptor<AppLayerConfig>()).first
    }

    func security() -> Manager.Security {
        Manager.Security(modelContainer: self.container, keyManager: self.keys)
    }

    /// Every verifier the config holds, by name: the two scalars and both arrays' slots.
    func verifiers() -> [String: Data] {
        guard let config = self.config() else { return [:] }

        var out: [String: Data] = [:]
        if let normal = config.sealedNormalVerifier { out["normal"] = normal }
        if let duress = config.sealedDuressVerifier { out["duress"] = duress }
        for (index, slot) in config.sealedNormalVerifiers.enumerated() { out["normals[\(index)]"] = slot }
        for (index, slot) in config.sealedDuressVerifiers.enumerated() { out["duresses[\(index)]"] = slot }
        return out
    }

    /// The distinct sizes of everything `verifiers()` holds.
    func sizes() -> Set<Int> {
        Set(self.verifiers().values.map(\.count))
    }

    /// What the previous release does on a downgrade: it doesn't know the wrap, so `configurePIN` writes a plain
    /// verifier of a new PIN over the master slot and the scalar, and the rest of the arrays stays as it was.
    func writePlainMasterPIN(_ pin: String) throws {
        let context = self.newContext()
        let config  = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        let plain   = FrozenPIN.plain(pin, label: FrozenPIN.normalLabel)
        config.sealedNormalVerifier = plain
        config.writeNormalVerifier(plain, at: 0)
        try context.save()
    }

    /// What a build that has the wrap writes into an unused slot: 81 random bytes, which open under no key.
    func writeWrappedFiller(atNormal index: Int) throws {
        let context = self.newContext()
        let config  = try #require(try context.fetch(FetchDescriptor<AppLayerConfig>()).first)
        config.sealedNormalVerifiers[index] = Sealing.random(81)
        try context.save()
    }

    /// Run the launch sequence over this store, as the app does before `Manager.Security`.
    @discardableResult
    func launch(batchSize: Int = 7) -> LaunchSequence.Report {
        LaunchSequence.run(context: self.newContext(), keyManager: self.keys, batchSize: batchSize)
    }
}

@MainActor
private func prepareVerifiers(_ form: KeyForm, seeded: Bool = true) throws -> (keys: TestKeyManager, store: VerifierStore) {
    let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
    keys.become(form)
    return (keys, try VerifierStore(keys: keys, seeded: seeded))
}

private func verifierReport(_ report: LaunchSequence.Report, sourceLocation: SourceLocation = #_sourceLocation) -> KeyReseal.VerifierReport? {
    switch report.verifiers {
    case .success(let value):
        return value
    case .failure(let error):
        Issue.record("the verifier wrap failed: \(error)", sourceLocation: sourceLocation)
        return nil
    }
}

// MARK: - The pins, and PINManager

@Suite("PIN verifier wrap — format", .ambientFrozenTestKeyManager)
@MainActor
struct PINVerifierFormatTests {

    @Test("Pin: the frozen inner key and the wrap keys of both forms are the pinned bytes (passes today)", arguments: KeyForm.allCases)
    func keysArePinned(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)

        #expect(keyBytes(try #require(try keys.deriveSecureModeKey())) == keyBytes(FrozenPIN.innerKey))
        #expect(keyBytes(try #require(try keys.enclaveBoundKey(.secureModeWrap))) == keyBytes(Frozen.pinWrapKey(form)))
    }

    @Test("Pin: the previous release's verifier is 53 bytes, and PINManager checks it with or without a wrap key (passes today)",
          arguments: KeyForm.allCases)
    func plainVerifierChecksAsToday(form: KeyForm) throws {
        let plain = FrozenPIN.plain("123456", label: FrozenPIN.normalLabel)
        #expect(plain.count == 53)

        for wrapKey in [nil, Frozen.pinWrapKey(form)] {
            #expect(Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: plain, seKey: FrozenPIN.innerKey, wrapKey: wrapKey))
            #expect(!Manager.PINManager.checkVerifier(pin: "123457", label: FrozenPIN.normalLabel, verifier: plain, seKey: FrozenPIN.innerKey, wrapKey: wrapKey))
            #expect(!Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.duressLabel, verifier: plain, seKey: FrozenPIN.innerKey, wrapKey: wrapKey))
        }
    }

    @Test("A wrapped verifier is 81 bytes, and checking opens the wrap and then the inner layer", arguments: KeyForm.allCases)
    func checkAcceptsAWrappedVerifier(form: KeyForm) throws {
        let wrapped = FrozenPIN.wrapped(FrozenPIN.plain("123456", label: FrozenPIN.normalLabel), form: form)
        #expect(wrapped.count == 81)

        let wrapKey = Frozen.pinWrapKey(form)
        #expect(Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: wrapped, seKey: FrozenPIN.innerKey, wrapKey: wrapKey))
        #expect(!Manager.PINManager.checkVerifier(pin: "654321", label: FrozenPIN.normalLabel, verifier: wrapped, seKey: FrozenPIN.innerKey, wrapKey: wrapKey), "a wrong PIN stays wrong")
        #expect(!Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.duressLabel, verifier: wrapped, seKey: FrozenPIN.innerKey, wrapKey: wrapKey), "and so does the other label")
        #expect(!Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: wrapped, seKey: FrozenPIN.innerKey, wrapKey: nil), "no wrap key, no check")
        #expect(!Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: wrapped, seKey: FrozenPIN.innerKey, wrapKey: SymmetricKey(size: .bits256)), "and another wrap key doesn't open it")
    }

    @Test("Checking rejects anything that is neither 53 nor 81 bytes, and random bytes of either size", arguments: KeyForm.allCases)
    func checkRejectsFiller(form: KeyForm) throws {
        let wrapKey = Frozen.pinWrapKey(form)
        for size in [0, 28, 52, 54, 80, 82, 200, 53, 81] {
            let bytes = Sealing.random(size)
            #expect(!Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: bytes, seKey: FrozenPIN.innerKey, wrapKey: wrapKey), "\(size) bytes")
        }
    }

    @Test("In a wrapped process PINManager builds an 81-byte verifier that opens as the frozen format says", arguments: KeyForm.allCases)
    func buildsWrapped(form: KeyForm) throws {
        Manager.Ambient.setPINVerifiers(.wrapped)

        let built = try Manager.PINManager.buildVerifier(pin: "123456", label: FrozenPIN.normalLabel, seKey: FrozenPIN.innerKey, wrapKey: Frozen.pinWrapKey(form))
        #expect(built.count == 81)

        // The format, independent of PINManager: the wrap opens, with no AAD, to a plain verifier of the PIN.
        let inner = try #require(FrozenPIN.unwrapped(built, form: form))
        #expect(inner.count == 53)
        #expect(FrozenPIN.opensAsPlain(inner, pin: "123456", label: FrozenPIN.normalLabel))
        #expect(Manager.PINManager.checkVerifier(pin: "123456", label: FrozenPIN.normalLabel, verifier: built, seKey: FrozenPIN.innerKey, wrapKey: Frozen.pinWrapKey(form)))
    }

    @Test("In a wrapped process a verifier can't be built without the wrap key: nothing falls back to 53 bytes")
    func wrappedBuildNeedsTheWrapKey() throws {
        Manager.Ambient.setPINVerifiers(.wrapped)

        #expect(throws: (any Error).self) {
            try Manager.PINManager.buildVerifier(pin: "123456", label: FrozenPIN.normalLabel, seKey: FrozenPIN.innerKey, wrapKey: nil)
        }
    }

    @Test("In a plain process PINManager builds 53 bytes even when it is given a wrap key: an array is never mixed", arguments: KeyForm.allCases)
    func plainBuildIgnoresTheWrapKey(form: KeyForm) throws {
        Manager.Ambient.setPINVerifiers(.plain)

        let built = try Manager.PINManager.buildVerifier(pin: "123456", label: FrozenPIN.normalLabel, seKey: FrozenPIN.innerKey, wrapKey: Frozen.pinWrapKey(form))
        #expect(built.count == 53)
        #expect(FrozenPIN.opensAsPlain(built, pin: "123456", label: FrozenPIN.normalLabel))
    }

    @Test("The sizes follow the process: 53 plain, 81 wrapped, for a verifier and for filler, and the two are equal")
    func sizesFollowTheProcess() {
        Manager.Ambient.setPINVerifiers(.plain)
        #expect(Manager.PINManager.verifierSize == 53 && AppLayerConfig.verifierFillerSize == 53)
        #expect(AppLayerConfig.verifierFiller().count == 53)

        Manager.Ambient.setPINVerifiers(.wrapped)
        #expect(Manager.PINManager.verifierSize == 81 && AppLayerConfig.verifierFillerSize == 81)
        #expect(AppLayerConfig.verifierFiller().count == 81)
        #expect(AppLayerConfig.verifierFillerArray().allSatisfy { $0.count == 81 } && AppLayerConfig.verifierFillerArray().count == AppLayerConfig.maxDepthCount)
    }

    @Test("A fresh AppLayerConfig in a wrapped process has all 64 slots at 81 bytes")
    func freshConfigFollowsTheProcess() {
        Manager.Ambient.setPINVerifiers(.wrapped)

        let config = AppLayerConfig()
        #expect(Set(config.sealedNormalVerifiers.map(\.count) + config.sealedDuressVerifiers.map(\.count)) == [81])
    }
}

// MARK: - The pass

@Suite("PIN verifier wrap — the pass", .ambientFrozenTestKeyManager)
@MainActor
struct PINVerifierWrapPassTests {

    @Test("The fixture is the previous release's: every slot and both scalars are 53 bytes, and the PINs verify (passes today)")
    func fixtureIsPlain() throws {
        let (_, store) = try prepareVerifiers(.hybrid)
        #expect(store.sizes() == [53])
        #expect(store.verifiers().count == 66)

        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth))
        }
    }

    @Test("The pass seals every slot and both scalars under the wrap key, 53 to 81 bytes, with the inner verifier inside unchanged",
          arguments: KeyForm.allCases)
    func wrapsEverything(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        let before = store.verifiers()

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .wrapped)
        #expect(report.wrapped == 66 && report.failed == 0 && report.left == 0)
        #expect(store.sizes() == [81])

        let after = store.verifiers()
        #expect(Set(after.keys) == Set(before.keys), "no slot appears or goes")
        for (name, old) in before {
            let inner = after[name].flatMap { FrozenPIN.unwrapped($0, form: form) }
            #expect(inner == old, "\(name): the wrap opens to exactly the verifier that was there")
        }
    }

    @Test("All 66 values change in the one commit; none keeps its bytes", arguments: KeyForm.allCases)
    func everythingChanges(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        let before = store.verifiers()

        try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        let after = store.verifiers()
        let kept = before.keys.filter { before[$0] == after[$0] }.sorted()
        #expect(kept.isEmpty, "unchanged: \(shown(kept))")
    }

    @Test("A wrapped slot doesn't open with the inner key alone, and doesn't open without r_U", arguments: KeyForm.allCases)
    func slotsNeedTheWrapKey(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        #expect(store.sizes() == [81], "the pass has to have run for \"doesn't open\" to mean anything")

        // The key a holder of the PIN Enclave key's public point can compute, and the same manager with another r_U.
        let other = TestKeyManager(
            scalars: Frozen.scalars, tierSecretU: Sealing.random(32), tierSecretB: Frozen.tierSecretB,
            tierPQRecordU: form == .hybrid ? Frozen.recordU : .classical, tierPQRecordB: .classical
        )
        let withoutSecret = try #require(try other.enclaveBoundKey(.secureModeWrap))

        for (name, slot) in store.verifiers() {
            #expect(FrozenPIN.unwrapped(slot, form: form) != nil, "\(name) opens under the wrap key")
            #expect(Sealing.open(slot, key: withoutSecret, aad: nil) == nil, "\(name) must not open under a wrap key made with another r_U")
            for pin in VerifierStore.pins {
                for label in [FrozenPIN.normalLabel, FrozenPIN.duressLabel] {
                    #expect(!FrozenPIN.opensAsPlain(slot, pin: pin, label: label), "\(name) tested with the inner key alone")
                }
            }
        }
    }

    @Test("A run with nothing at 53 bytes reads nothing and writes nothing", arguments: KeyForm.allCases)
    func secondRunDoesNothing(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        let before = store.verifiers()

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .alreadyDone)
        #expect(store.verifiers() == before)
    }

    @Test("Interrupted at each point: the store is untouched, the PINs still verify, the relaunch wraps, and a third run changes no byte",
          arguments: KeyReseal.WrapFaultPoint.allCases, KeyForm.allCases)
    func interruptionLosesNothing(point: KeyReseal.WrapFaultPoint, form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        let before = store.verifiers()

        let faults = KeyReseal.Faults(interruptAtWrap: point)
        var thrown: (any Error)?
        do {
            try KeyReseal.$faults.withValue(faults) {
                try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
            }
        } catch {
            thrown = error
        }

        #expect(faults.reachedWrap.contains(point), "the pass never reached \(point)")
        #expect((thrown as? KeyReseal.InjectedWrapFault)?.point == point, "the pass was to be interrupted at \(point)")
        #expect(store.verifiers() == before, "an interruption leaves every byte as it was: one commit, or none")

        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth), "PIN \(depth) after an interruption at \(point)")
        }

        let second = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        #expect(second.outcome == .wrapped)
        #expect(store.sizes() == [81])

        let wrapped = store.verifiers()
        let third = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        #expect(third.outcome == .alreadyDone)
        #expect(store.verifiers() == wrapped)
    }

    @Test("Each new ciphertext is opened and compared before it replaces the old: a corrupt sealer leaves every old byte and reports it",
          arguments: KeyForm.allCases)
    func readBackBeforeReplace(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        let before = store.verifiers()

        let report = try KeyReseal.$faults.withValue(KeyReseal.Faults(corruptsNewCiphertext: true)) {
            try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        }

        #expect(report.outcome == .incomplete)
        #expect(report.failed > 0 && report.wrapped == 0)
        #expect(store.verifiers() == before, "not one byte may change when the new ciphertexts are bad")
        #expect(store.sizes() == [53])
    }

    @Test("The wrap key unavailable: nothing is written, the PINs still verify, and the next run wraps", arguments: KeyForm.allCases)
    func wrapKeyUnavailable(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        let before = store.verifiers()
        keys.simulatesWrapKeyUnavailable = true

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .aborted(.wrapKeyUnavailable))
        #expect(store.verifiers() == before)
        let security = store.security()
        for (depth, pin) in VerifierStore.pins.enumerated() {
            #expect(try security.verify(pin) == .normal(depth: depth))
        }

        keys.simulatesWrapKeyUnavailable = false
        #expect(try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys).outcome == .wrapped)
        #expect(store.sizes() == [81])
    }

    @Test("With the PIN Enclave key unavailable altogether the pass aborts too, and writes nothing")
    func secureModeKeyUnavailable() throws {
        let (keys, store) = try prepareVerifiers(.hybrid)
        let before = store.verifiers()
        keys.simulatesSecureModeKeyUnavailable = true

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .aborted(.wrapKeyUnavailable))
        #expect(store.verifiers() == before)

        let security = store.security()
        #expect(throws: Manager.Security.SecurityError.keyDerivationFailed) { try security.verify("111111") }
        #expect(throws: Manager.Security.SecurityError.keyDerivationFailed) { try security.configurePIN("555555") }
        #expect(store.verifiers() == before, "and a PIN operation that can't derive its key writes nothing either")
    }

    @Test("No config row: nothing to wrap")
    func configMissing() throws {
        let (keys, store) = try prepareVerifiers(.hybrid, seeded: false)

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .aborted(.configMissing))
    }

    @Test("A store with no PIN at all (random filler in every slot, nil scalars) wraps like any other, so installs look alike",
          arguments: KeyForm.allCases)
    func noPINConfigured(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form, seeded: false)
        let context = store.newContext()
        context.insert(AppLayerConfig())
        try context.save()
        #expect(store.sizes() == [53] && store.verifiers().count == 64)

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .wrapped)
        #expect(store.sizes() == [81] && store.verifiers().count == 64, "the scalars stay nil")
    }

    @Test("Mixed sizes, as a downgrade leaves them: every value changes in the commit, whatever its size was",
          arguments: KeyForm.allCases)
    func mixedStoreChangesWhole(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)
        try store.writePlainMasterPIN("999999")
        try store.writeWrappedFiller(atNormal: 10)
        #expect(store.sizes() == [53, 81], "precondition: the previous release wrote one 53-byte verifier into an 81-byte store")
        let before = store.verifiers()

        let report = try KeyReseal.wrapVerifiers(context: store.newContext(), keyManager: keys)

        #expect(report.outcome == .wrapped)
        #expect(report.wrapped == 2, "the slot and the scalar the previous release wrote")
        #expect(report.refreshed == 1, "the 81 random bytes, which open under no key, replaced by fresh ones")
        #expect(report.rewritten == 63, "and every other wrapped value sealed again with a fresh nonce")
        #expect(store.sizes() == [81])
        let kept = before.keys.filter { before[$0] == store.verifiers()[$0] }.sorted()
        #expect(kept.isEmpty, "a run that changed only the slots the previous release wrote would show which are real: \(shown(kept))")
    }
}

// MARK: - The launch, and Security over a wrapped store

@Suite("PIN verifier wrap — launch and Manager.Security", .ambientFrozenTestKeyManager)
@MainActor
struct PINVerifierLaunchTests {

    @Test("After the launch sequence every PIN verifies at depths 0, 1 and 3, with the same results as before",
          arguments: KeyForm.allCases, [0, 1, 3])
    func pinsVerifyAfterTheWrap(form: KeyForm, depth: Int) throws {
        let (_, store) = try prepareVerifiers(form)

        let report = store.launch()
        #expect(verifierReport(report)?.outcome == .wrapped)
        #expect(store.sizes() == [81])
        #expect(Manager.Ambient.pinVerifiers == .wrapped)

        let security = store.security()
        #expect(try security.verify(VerifierStore.pins[depth]) == .normal(depth: depth))
        #expect(try security.verify("000000") == .wrong, "a wrong PIN stays wrong")
        #expect(!security.checkNormalPIN("000000") && security.checkNormalPIN(VerifierStore.pins[0]))
    }

    @Test("Duress verifiers (found only by scanning the duress array, with no routing alias) still verify after the wrap",
          arguments: KeyForm.allCases)
    func duressVerifiersStillVerify(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        let store = try VerifierStore(keys: keys, aliases: false)
        store.launch()
        #expect(store.sizes() == [81])

        // With the gate down, re-entering a duress PIN scans the duress array (step 2) and routes to the next depth.
        let security = store.security()
        try security.disablePIN(at: 0, confirmingPIN: VerifierStore.pins[0])
        #expect(security.reEnablePIN(VerifierStore.pins[1]), "the duress PIN of depth 0 matched a wrapped duress slot")
        #expect(security.currentDepth == 1)
    }

    @Test("Wrong PINs count and lock out exactly as before the wrap", arguments: KeyForm.allCases)
    func lockoutIsUnchanged(form: KeyForm) throws {
        let (_, store) = try prepareVerifiers(form)
        store.launch()
        #expect(store.sizes() == [81])

        let security = store.security()
        for attempt in 1...5 {
            #expect(try security.verify("000000") == .wrong)
            #expect(store.config()?.readLockoutCount() == attempt)
        }
        #expect(try security.verify("000000") == .wrong, "the sixth is still a wrong PIN; it sets the first lockout")
        #expect(store.config()?.readLockoutCount() == 6)
        guard case .locked = try security.verify(VerifierStore.pins[0]) else {
            Issue.record("the seventh attempt is locked out, even with the right PIN")
            return
        }
        #expect(store.config()?.readLockoutCount() == 6, "a locked attempt doesn't count")
    }

    @Test("Every Security operation in a wrapped process leaves all 64 slots and both scalars at 81 bytes, and works",
          arguments: KeyForm.allCases)
    func wrappedLifecycle(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil
        let store = try VerifierStore(keys: keys, seeded: false)
        store.launch()
        #expect(Manager.Ambient.pinVerifiers == .wrapped, "a fresh install ends wrapped")
        #expect(store.sizes() == [81])

        let security = store.security()
        func uniform(_ step: String, sourceLocation: SourceLocation = #_sourceLocation) {
            #expect(store.sizes() == [81], "\(step): \(store.sizes().sorted())", sourceLocation: sourceLocation)
        }

        try security.configurePIN("111111")
        uniform("configurePIN")
        try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999")
        uniform("activate")
        security.applyVerifyState(for: try security.verify("999999"))
        try security.activateSecureMode(confirmingEntryPIN: "999999", duressPIN: "777777")
        uniform("activate deeper")
        #expect(security.checkCurrentLayerPIN("999999") && !security.checkCurrentLayerPIN("000000"))
        try security.disablePIN(at: security.currentDepth, confirmingPIN: "999999")
        uniform("disablePIN")
        #expect(security.reEnablePIN("999999"))
        uniform("reEnablePIN, a known PIN")

        // An unknown PIN at a duress depth is accepted as a new layer (Bug 37): it writes two verifiers.
        try security.disablePIN(at: security.currentDepth, confirmingPIN: "999999")
        #expect(security.reEnablePIN("888888"))
        uniform("reEnablePIN, coercion acceptance")
        security.applyVerifyState(for: try security.verify("888888"))
        #expect(security.currentDepth == 2, "the new layer's PIN verifies")

        try security.deactivateSecureMode(confirmingEntryPIN: "888888")
        uniform("deactivateSecureMode")
        try security.forceDeactivateForRecovery(confirmingEntryPIN: "111111")
        uniform("forceDeactivateForRecovery")
        try security.deactivatePIN(confirmingNormalPIN: "111111")
        uniform("deactivatePIN")
    }

    @Test("In a plain process (the pass hasn't run) the same operations keep every slot at 53 bytes", arguments: KeyForm.allCases)
    func plainLifecycle(form: KeyForm) throws {
        let (_, store) = try prepareVerifiers(form, seeded: false)
        #expect(Manager.Ambient.pinVerifiers == .plain)
        let security = store.security()
        func uniform(_ step: String, sourceLocation: SourceLocation = #_sourceLocation) {
            #expect(store.sizes() == [53], "\(step): \(store.sizes().sorted())", sourceLocation: sourceLocation)
        }

        try security.configurePIN("111111");                                             uniform("configurePIN")
        try security.activateSecureMode(confirmingEntryPIN: "111111", duressPIN: "999999"); uniform("activate")
        security.applyVerifyState(for: try security.verify("999999"));                   uniform("verify")
        try security.deactivateSecureMode(confirmingEntryPIN: "999999");                 uniform("deactivateSecureMode")
        try security.deactivatePIN(confirmingNormalPIN: "111111");                       uniform("deactivatePIN")
    }

    @Test("A fresh install ends uniformly at 81 bytes, and a PIN configured on it is wrapped", arguments: KeyForm.allCases)
    func freshInstall(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        keys.tierSecretU   = nil
        keys.tierPQRecordU = nil
        let store = try VerifierStore(keys: keys, seeded: false)

        let report = store.launch()

        #expect(verifierReport(report)?.outcome == .alreadyDone, "the bootstrap's config row is born wrapped, so there is nothing to wrap")
        #expect(store.sizes() == [81] && store.verifiers().count == 64)
        #expect(Manager.Ambient.pinVerifiers == .wrapped)

        let security = store.security()
        try security.configurePIN("111111")
        #expect(store.sizes() == [81] && store.verifiers().count == 65, "the normal scalar is wrapped too; the duress scalar stays nil until a layer exists")
        #expect(try store.security().verify("111111") == .normal(depth: 0))
    }

    @Test("An install old enough to have empty verifier arrays and 53-byte scalars: the scalar is wrapped, and Security fills the arrays at 81",
          arguments: KeyForm.allCases)
    func scalarOnlyInstall(form: KeyForm) throws {
        let (_, store) = try prepareVerifiers(form, seeded: false)
        let context = store.newContext()
        let config  = AppLayerConfig()
        config.sealedNormalVerifiers = []
        config.sealedDuressVerifiers = []
        config.sealedNormalVerifier  = FrozenPIN.plain("111111", label: FrozenPIN.normalLabel)
        config.sealedDuressVerifier  = FrozenPIN.plain("999999", label: FrozenPIN.duressLabel)
        context.insert(config)
        try context.save()

        store.launch()
        let security = store.security()

        #expect(store.sizes() == [81] && store.verifiers().count == 66, "the migration in Security.init copied the scalar into the array and filled the rest at 81")
        #expect(try security.verify("111111") == .normal(depth: 0))
    }

    @Test("The wrap key unavailable at launch: the store stays at 53, the process writes 53, PINs verify, and the next launch wraps",
          arguments: KeyForm.allCases)
    func wrapKeyUnavailableAtLaunch(form: KeyForm) throws {
        let (keys, store) = try prepareVerifiers(form)
        keys.simulatesWrapKeyUnavailable = true

        let report = store.launch()

        #expect(verifierReport(report)?.outcome == .aborted(.wrapKeyUnavailable))
        #expect(Manager.Ambient.pinVerifiers == .plain)
        #expect(store.sizes() == [53])
        let security = store.security()
        #expect(try security.verify("333333") == .normal(depth: 2))

        // A new verifier is written plain, so the array stays uniform.
        try security.deactivateSecureMode(confirmingEntryPIN: "111111")
        #expect(store.sizes() == [53])
        try security.configurePIN("555555")
        #expect(store.sizes() == [53])

        keys.simulatesWrapKeyUnavailable = false
        let next = store.launch()
        #expect(verifierReport(next)?.outcome == .wrapped)
        #expect(Manager.Ambient.pinVerifiers == .wrapped)
        #expect(store.sizes() == [81])
        #expect(try store.security().verify("555555") == .normal(depth: 0))
    }

    @Test("Re-upgrade: a 53-byte verifier the previous release wrote into a wrapped store is wrapped at the next launch, and all else verifies",
          arguments: KeyForm.allCases)
    func reUpgrade(form: KeyForm) throws {
        let (_, store) = try prepareVerifiers(form)
        store.launch()
        #expect(store.sizes() == [81])

        // The downgrade: the previous release can't read the 81-byte verifiers, and writes a plain one for a new PIN.
        try store.writePlainMasterPIN("999999")
        #expect(store.sizes() == [53, 81])
        let before = store.verifiers()

        store.launch()

        #expect(store.sizes() == [81])
        #expect(Manager.Ambient.pinVerifiers == .wrapped)
        let kept = before.keys.filter { before[$0] == store.verifiers()[$0] }.sorted()
        #expect(kept.isEmpty, "every value changed in the commit: \(shown(kept))")

        let security = store.security()
        #expect(try security.verify("999999") == .normal(depth: 0), "the PIN the previous release wrote")
        #expect(try security.verify(VerifierStore.pins[2]) == .normal(depth: 2), "and the layers it left alone")
    }

    @Test("A launch whose tier U pass threw wraps nothing and still reads the store's sizes")
    func thrownTierUPassSkipsTheWrap() throws {
        let (_, store) = try prepareVerifiers(.hybrid)
        let before = store.verifiers()

        let report = KeyReseal.$faults.withValue(KeyReseal.Faults(interruptAt: .afterFirstRow)) { store.launch() }

        guard case .failure = report.reseal else {
            Issue.record("the tier U pass was to be cut short")
            return
        }
        #expect(verifierReport(report)?.outcome == .notRun)
        #expect(store.verifiers() == before)
        #expect(Manager.Ambient.pinVerifiers == .plain)
    }
}
