//
//  ComposeStagingTests.swift
//  OccultaTests
//
//  Attachments staged for a recipient with no per-contact key (a group, or a contact we hold no
//  public key for) used to be written to tmp/ and copied into Drafts/ as plaintext, and videos
//  were refused outright ("Secure storage not ready."). They are now sealed under the compose
//  staging key. The key is injected, so none of this needs a Secure Enclave.
//
//  Since Bug 171, Stage 8 that key is tier U's (`EnclaveBoundKey.composeStaging`, the local DB Enclave key and `r_U`),
//  reached through `TierUComposeStagingKey`, and it exists only in a process whose tier U keys are Enclave-bound.
//

import Testing
import CryptoKit
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

// MARK: - Helpers

private struct FixedStagingKey: ComposeStagingKeyProviding {
    let key = SymmetricKey(size: .bits256)
    func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
}

private struct NoStagingKey: ComposeStagingKeyProviding {
    func deriveComposeStagingKey() throws -> SymmetricKey { throw ImportError.stagingKeyUnavailable }
}

/// Several 256 KB chunks of recognisable bytes, so the "no plaintext on disk" scan is meaningful.
private func makePlaintext() -> (data: Data, marker: Data) {
    let marker = Data("PLAINTEXT-MARKER-\(UUID().uuidString)".utf8)
    var data = Data()
    while data.count < 600_000 { data.append(marker) }
    return (data, marker)
}

private func scratchDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("compose-staging-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func containsMarker(in directory: URL, _ marker: Data) -> Bool {
    let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
    return files.contains { url in
        guard let raw = try? Data(contentsOf: url) else { return false }
        return raw.range(of: marker) != nil
    }
}

@MainActor
private func makeContactManager() throws -> ContactManager {
    let schema = Schema([
        Group.self,
        Contact.Profile.self,
        Contact.Profile.PhoneNumber.self,
        Contact.Profile.EmailAddress.self,
        Contact.Profile.PostalAddress.self,
        Contact.Profile.URLAddress.self,
        Contact.Profile.Key.self,
    ])
    let container = try ModelContainer(for: schema, configurations: ModelConfiguration(isStoredInMemoryOnly: true))
    let security  = Manager.Security(modelContainer: container, keyManager: TestKeyManager())
    return ContactManager(modelContainer: container, security: security)
}

@MainActor
private func makeMember(identifier: String) throws -> Contact.Profile? {
    guard let encryptedKey = try Manager.Crypto().encrypt(data: try TestKeyManager().retrieveIdentity()) else { return nil }
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
    )]
    return profile
}

@MainActor
private func stage(_ plaintext: Data, using vm: ComposeViewModel, in directory: URL) async throws -> OccultaFormats.File {
    let source = directory.appendingPathComponent("source-\(UUID().uuidString).bin")
    try plaintext.write(to: source)
    let staged = directory.appendingPathComponent("staged-\(UUID().uuidString).mp4")
    try await ComposeViewModel.seal(contentsOf: source, to: staged, using: try #require(vm.attachmentManager))
    try FileManager.default.removeItem(at: source)
    return OccultaFormats.File(url: staged, format: .file(.init(name: "clip", extension: "mp4")), date: Date())
}

// MARK: - Setup

@Suite("ComposeViewModel — staging key")
@MainActor struct ComposeStagingSetupTests {

    @Test("group gets a manager, and a sealed file round-trips to the original bytes", .ambientTestKeyManager)
    func groupSealsAndRoundTrips() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())

        let file = try await stage(plain, using: vm, in: dir)
        let url  = try #require(file.url)

        #expect(AttachmentManager.isSealed(at: url))
        #expect(!containsMarker(in: dir, marker))
        #expect(try await vm.attachmentManager?.data(at: url) == plain)
    }

    @Test("images are sealed too (in-memory path)", .ambientTestKeyManager)
    func groupImageIsSealed() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())

        let url = dir.appendingPathComponent("image.jpg")
        let manager = try #require(vm.attachmentManager)
        try manager.encrypt(plain, to: url)

        #expect(AttachmentManager.isSealed(at: url))
        #expect(!containsMarker(in: dir, marker))
        #expect(try await manager.data(at: url) == plain)
    }

    @Test("a contact we hold no key for falls back to the staging key", .ambientTestKeyManager)
    func keylessContactGetsManager() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let vm = ComposeViewModel(recipient: .contact("never-met"), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())

        let file = try await stage(plain, using: vm, in: dir)

        #expect(vm.attachmentManager != nil)
        #expect(!containsMarker(in: dir, marker))
        #expect(try await vm.attachmentManager?.data(at: try #require(file.url)) == plain)
    }

    @Test("with no key available there is no manager, and encrypting a staged file fails closed", .ambientTestKeyManager)
    func noKeyFailsClosed() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: NoStagingKey())
        let cm = try makeContactManager()
        vm.setup(contactManager: cm)
        #expect(vm.attachmentManager == nil)

        let stray = dir.appendingPathComponent("stray.bin")
        try Data("anything".utf8).write(to: stray)
        vm.messages = [OccultaFormats.File(url: stray, format: .file(.init(name: "stray", extension: "bin")), date: Date())]
        await vm.encrypt(contactManager: cm)

        #expect(vm.encryptedURL == nil)
        #expect(vm.isShowingError)
    }
}

// MARK: - Group send

@Suite("ComposeViewModel — group send with sealed attachments")
@MainActor struct ComposeStagingGroupSendTests {

    @Test("a staged video is read back through the manager and the bundle is built", .ambientTestKeyManager)
    func groupBundleIsBuilt() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let cm = try makeContactManager()
        try cm.insertProfile(try #require(try makeMember(identifier: "alice")))
        let group = try cm.createGroup(name: "G")
        try group.addMember("alice", atDepth: 0)

        let vm = ComposeViewModel(recipient: .group(try #require(group.readID())), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: cm)
        vm.messages = [try await stage(plain, using: vm, in: dir)]

        await vm.encrypt(contactManager: cm)

        let out = try #require(vm.encryptedURL, "encrypt failed: \(vm.errorMessage)")
        defer { try? FileManager.default.removeItem(at: out) }
        let bundle = try OccultaBundle.decoded(from: try Data(contentsOf: out))
        #expect(bundle.group?.recipients.count == 1)
        #expect(try Data(contentsOf: out).range(of: marker) == nil)
        #expect(!containsMarker(in: dir, marker))
    }
}

// MARK: - Drafts

@Suite("ComposeViewModel — drafts with staged attachments")
@MainActor struct ComposeStagingDraftTests {

    private func makeContext() throws -> ModelContext {
        let schema = Schema([Message.Draft.self])
        let container = try ModelContainer(for: schema, configurations: [ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)])
        return ModelContext(container)
    }

    @Test("a group draft's attachment is sealed in Drafts/ and restores after a relaunch", .ambientTestKeyManager)
    func groupDraftRestores() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let context = try makeContext()
        let provider = FixedStagingKey()
        let cm = try makeContactManager()

        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: provider)
        vm.setup(contactManager: cm)
        vm.messages = [try await stage(plain, using: vm, in: dir)]

        let store = DraftStore()
        await store.flush(
            recipientID: vm.recipientIDString, isSensitive: false, text: "hi",
            messages: vm.messages, useThread: false, modelContext: context
        )
        let row = try #require(Message.Draft.find(recipientID: vm.recipientIDString, in: context))
        defer { Message.Draft.delete(row, in: context) }
        #expect(!containsMarker(in: Message.Draft.attachmentsFolder(for: row.id), marker))

        // Relaunch: new view model, new store, same staging key.
        let relaunched = ComposeViewModel(recipient: vm.recipient, stagingKeyProvider: provider)
        relaunched.setup(contactManager: cm)
        let loaded = try #require(DraftStore().load(recipientID: vm.recipientIDString, modelContext: context))
        await relaunched.adopt(draftMessages: loaded.messages)

        let restored = try #require(relaunched.messages.first?.url)
        #expect(relaunched.messages.count == 1)
        #expect(try await relaunched.attachmentManager?.data(at: restored) == plain)
    }

    @Test("a plaintext draft attachment from an earlier build is sealed in place, not lost", .ambientTestKeyManager)
    func legacyPlaintextIsUpgraded() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()
        let legacy = dir.appendingPathComponent("legacy.mp4")
        try plain.write(to: legacy)

        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())
        let file = OccultaFormats.File(url: legacy, format: .file(.init(name: "clip", extension: "mp4")), date: Date())
        await vm.adopt(draftMessages: [file])

        #expect(vm.messages.count == 1)
        #expect(AttachmentManager.isSealed(at: legacy))
        #expect(!containsMarker(in: dir, marker))
        #expect(try await vm.attachmentManager?.data(at: legacy) == plain)
        #expect(!FileManager.default.fileExists(atPath: legacy.appendingPathExtension("sealing").path))
    }

    @Test("an already sealed attachment is left byte for byte untouched", .ambientTestKeyManager)
    func sealedIsNotResealed() async throws {
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())
        let file = try await stage(makePlaintext().data, using: vm, in: dir)
        let url  = try #require(file.url)
        let before = try Data(contentsOf: url)

        await vm.adopt(draftMessages: [file])

        #expect(try Data(contentsOf: url) == before)
        #expect(vm.messages.count == 1)
    }

    @Test("a draft attachment whose file is gone is dropped instead of dangling", .ambientTestKeyManager)
    func missingFileIsDropped() async throws {
        let vm = ComposeViewModel(recipient: .group(UUID()), stagingKeyProvider: FixedStagingKey())
        vm.setup(contactManager: try makeContactManager())
        let gone = FileManager.default.temporaryDirectory.appendingPathComponent("gone-\(UUID().uuidString).mp4")
        await vm.adopt(draftMessages: [
            OccultaFormats.File(url: gone, format: .file(.init(name: "clip", extension: "mp4")), date: Date())
        ])
        #expect(vm.messages.isEmpty)
    }
}

// MARK: - Tier U's key

@Suite("ComposeViewModel — the tier U staging key", .ambientFrozenTestKeyManager)
@MainActor struct ComposeStagingViewModelTierUTests {

    @Test("with the default provider a group seals under tier U's key and a sealed file round-trips, in each form",
          arguments: KeyForm.allCases)
    func defaultProviderRoundTrips(form: KeyForm) async throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        Manager.Ambient.setTierUKeys(.enclaveBound)
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()

        let vm = ComposeViewModel(recipient: .group(UUID()))
        vm.setup(contactManager: try makeContactManager())
        let file = try await stage(plain, using: vm, in: dir)
        let url  = try #require(file.url)

        #expect(AttachmentManager.isSealed(at: url))
        #expect(!containsMarker(in: dir, marker))
        #expect(try await vm.attachmentManager?.data(at: url) == plain)

        // It is under the pinned key of this form, and not under the other form's.
        #expect(try await AttachmentManager(contactKey: Frozen.composeKey(form)).data(at: url) == plain)
        let other: KeyForm = form == .hybrid ? .classical : .hybrid
        await #expect(throws: (any Error).self) { _ = try await AttachmentManager(contactKey: Frozen.composeKey(other)).data(at: url) }
    }

    @Test("a contact we hold no key for seals under it too", arguments: KeyForm.allCases)
    func keylessContact(form: KeyForm) async throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        Manager.Ambient.setTierUKeys(.enclaveBound)
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()

        let vm = ComposeViewModel(recipient: .contact("never-met"))
        vm.setup(contactManager: try makeContactManager())
        let file = try await stage(plain, using: vm, in: dir)

        #expect(!containsMarker(in: dir, marker))
        #expect(try await vm.attachmentManager?.data(at: try #require(file.url)) == plain)
    }

    @Test("in a process the reseal left on the legacy keys there is no manager, no import is possible and encrypting a staged file fails closed",
          arguments: [true, false])
    func legacyStateFailsClosed(group: Bool) async throws {
        Manager.Ambient.setTierUKeys(.legacy)
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }

        let vm = ComposeViewModel(recipient: group ? .group(UUID()) : .contact("never-met"))
        let cm = try makeContactManager()
        vm.setup(contactManager: cm)
        #expect(vm.attachmentManager == nil, "no key, so no manager: every import path refuses (\"Secure storage not ready.\")")

        let stray = dir.appendingPathComponent("stray.bin")
        try Data("anything".utf8).write(to: stray)
        vm.messages = [OccultaFormats.File(url: stray, format: .file(.init(name: "stray", extension: "bin")), date: Date())]
        await vm.encrypt(contactManager: cm)

        #expect(vm.encryptedURL == nil)
        #expect(vm.isShowingError)
        #expect(FileManager.default.fileExists(atPath: stray.path), "and nothing was deleted")
    }

    @Test("adopting a draft without a manager keeps its file references and deletes nothing: sealed, and plaintext from an earlier build alike")
    func adoptWithoutAManagerKeepsEverything() async throws {
        Manager.Ambient.setTierUKeys(.legacy)
        let dir = try scratchDirectory(); defer { try? FileManager.default.removeItem(at: dir) }
        let (plain, marker) = makePlaintext()

        let sealed = dir.appendingPathComponent("sealed.mp4")
        try AttachmentManager(contactKey: Frozen.composeKey(.hybrid)).encrypt(plain, to: sealed)
        let plaintext = dir.appendingPathComponent("plaintext.mp4")
        try plain.write(to: plaintext)
        let before = [sealed, plaintext].map { try? Data(contentsOf: $0) }
        let files = [sealed, plaintext].map {
            OccultaFormats.File(url: $0, format: .file(.init(name: "clip", extension: "mp4")), date: Date())
        }

        let vm = ComposeViewModel(recipient: .group(UUID()))
        vm.setup(contactManager: try makeContactManager())
        #expect(vm.attachmentManager == nil)
        await vm.adopt(draftMessages: files)

        #expect(vm.messages.map(\.url) == files.map(\.url), "the references are the draft's own")
        #expect([sealed, plaintext].map { try? Data(contentsOf: $0) } == before, "no file was touched or deleted")
        #expect(containsMarker(in: dir, marker), "the plaintext file is still there for a later launch to seal")
        #expect(!FileManager.default.fileExists(atPath: plaintext.appendingPathExtension("sealing").path))
    }
}

// MARK: - Key derivation

@Suite("Compose staging key — not the share session key", .ambientFrozenTestKeyManager)
@MainActor
struct ComposeStagingKeyDerivationTests {

    /// A share-staging key manager on a software Enclave key and items of its own, so it needs no Secure Enclave.
    private func stagingManager(hybrid: Bool) throws -> (manager: ShareStagingKeyManager, clean: () -> Void) {
        let suffix = UUID().uuidString
        let key = try softwareP256Key(scalar: katScalar)
        let manager = ShareStagingKeyManager(
            keyTag: "test.compose.\(suffix)", tierSecretAccount: "test.compose.rs.\(suffix)", tierPQRecordAccount: "test.compose.pqs.\(suffix)",
            postQuantum: { hybrid ? InMemoryStagingPostQuantum() : nil }, enclaveKey: { key }
        )
        try manager.createTierItemsIfAbsent()
        return (manager, { manager.deleteTierSecret(); manager.deleteTierPQRecord() })
    }

    @Test("it is stable, 32 bytes, and distinct from the local DB key, the custody key and the share session keys (legacy and Enclave-bound)",
          .enabled(if: sharedKeychainAvailable()), arguments: KeyForm.allCases)
    func domainSeparated(form: KeyForm) throws {
        let keys = try #require(Manager.Ambient.keyManager as? TestKeyManager)
        keys.become(form)
        Manager.Ambient.setTierUKeys(.enclaveBound)
        let (staging, clean) = try self.stagingManager(hybrid: form == .hybrid)
        defer { clean() }

        let compose = try #require(try keys.deriveComposeStagingKey())
        #expect(keyBytes(compose) == keyBytes(try #require(try keys.deriveComposeStagingKey())), "stable")
        #expect(compose.bitCount == 256)

        let others: [String: SymmetricKey] = [
            "local DB":              try #require(try keys.createHybridLocalEncryptionKey()),
            "custody":               try #require(try keys.deriveShardCustodyKey()),
            "restore":               try #require(try keys.deriveRestoreVaultKey()),
            "session, legacy":       try staging.deriveLegacySymmetricKey(),
            "session, Enclave-bound": try staging.deriveEnclaveBoundKey(),
            "release's compose key": SymmetricKey(data: try rebuildLegacy(scalar: katScalar, secret: nil, info: Data("Occulta-v1-group-compose-staging-2026".utf8))),
        ]
        for (name, key) in others {
            #expect(keyBytes(key) != keyBytes(compose), "the compose key equals the \(name) key")
        }
    }
}
