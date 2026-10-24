//
//  MemoryGuardTests.swift
//  OccultaTests
//
//  STREAMING_SPEC §7. The inline layout refuses outright, before it takes a prekey or writes a file,
//  when the whole body cannot fit. `os_proc_available_memory` is injected.
//

import Testing
import CryptoKit
import Foundation
@testable import Occulta
@testable import OccultaFormats

private func guardReporting(_ available: Int) -> MemoryGuard {
    MemoryGuard { available }
}

private let MiB = 1024 * 1024

@Suite("MemoryGuard")
struct MemoryGuardTests {

    @Test("receive needs 2T + 64 MiB: refuses one byte short, allows the exact amount")
    func receiveThreshold() throws {
        let length = 300 * MiB
        let needed = 2 * length + 64 * MiB

        #expect(throws: OccultaBundle.BundleError.tooLargeForDevice) {
            try guardReporting(needed - 1).checkReceive(bundleLength: length)
        }
        try guardReporting(needed).checkReceive(bundleLength: length)
    }

    @Test("send needs 4P + 64 MiB: refuses one byte short, allows the exact amount")
    func sendThreshold() throws {
        let length = 200 * MiB
        let needed = 4 * length + 64 * MiB

        #expect(throws: MemoryGuard.SendRefusal.tooLargeToSend) {
            try guardReporting(needed - 1).checkSend(plaintextLength: length)
        }
        try guardReporting(needed).checkSend(plaintextLength: length)
    }

    @Test("an empty bundle still needs the headroom")
    func headroomAlone() throws {
        #expect(throws: OccultaBundle.BundleError.tooLargeForDevice) {
            try guardReporting(64 * MiB - 1).checkReceive(bundleLength: 0)
        }
        try guardReporting(64 * MiB).checkReceive(bundleLength: 0)
    }

    @Test("the refusals name no contact and no depth")
    func messagesAreGeneric() {
        let text = MemoryGuard.SendRefusal.tooLargeToSend.localizedDescription
        #expect(text == "This message is too large to send until the recipient updates Occulta.")
    }

    @Test("the production guard does not refuse a small bundle on this host")
    func systemGuardAllowsSmallBundle() throws {
        let available = MemoryGuard.system.availableMemory()
        #expect(available > 128 * MiB, "os_proc_available_memory reported \(available)")
        try MemoryGuard.system.checkReceive(bundleLength: 1024)
    }
}

// MARK: - A refused send changes nothing

@Suite("MemoryGuard — refused send")
@MainActor struct RefusedSendTests {

    private struct FixedStagingKey: ComposeStagingKeyProviding {
        let key = SymmetricKey(size: .bits256)
        func deriveComposeStagingKey() throws -> SymmetricKey { self.key }
    }

    private func makeGroup(_ cm: ContactManager) throws -> UUID {
        let encryptedKey = try #require(try Manager.Crypto().encrypt(data: try TestKeyManager().retrieveIdentity()))
        let profile = Contact.Profile(
            identifier: "alice", givenName: "", familyName: "", middleName: "",
            nickname: "", organizationName: "", departmentName: "", jobTitle: ""
        )
        profile.contactPublicKeys = [Contact.Profile.Key(
            material: encryptedKey, owner: Data(), date: Data(), quantumKeyMaterialEncrypted: nil
        )]
        try cm.insertProfile(profile)
        let group = try cm.createGroup(name: "G")
        try group.addMember("alice", atDepth: 0)
        return try #require(group.readID())
    }

    private func stagedVideo(in directory: URL, using vm: ComposeViewModel) async throws -> OccultaFormats.File {
        let source = directory.appendingPathComponent("source.bin")
        try Data(repeating: 0x5A, count: 600_000).write(to: source)
        let staged = directory.appendingPathComponent("staged.mp4")
        try await ComposeViewModel.seal(contentsOf: source, to: staged, using: try #require(vm.attachmentManager))
        try FileManager.default.removeItem(at: source)
        return OccultaFormats.File(url: staged, format: .file(.init(name: "clip", extension: "mp4")), date: Date())
    }

    private func outputs() -> Set<String> {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.temporaryDirectory.path)) ?? []
        return Set(names.filter { $0.hasSuffix(".occ") })
    }

    @Test("a send that cannot fit in memory writes no bundle and leaves the staged file alone", .ambientTestKeyManager)
    func refusedSendWritesNothing() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("guard-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let cm = try TestSupport.makeContactManager()
        let groupID = try makeGroup(cm)
        let vm = ComposeViewModel(
            recipient: .group(groupID), stagingKeyProvider: FixedStagingKey(), memoryGuard: guardReporting(10 * MiB)
        )
        vm.setup(contactManager: cm)
        let staged = try await stagedVideo(in: dir, using: vm)
        vm.messages = [staged]
        let before = self.outputs()
        let stagedBytes = try Data(contentsOf: try #require(staged.url))

        await vm.encrypt(contactManager: cm)

        #expect(vm.encryptedURL == nil)
        #expect(vm.isShowingError)
        #expect(vm.errorMessage == MemoryGuard.SendRefusal.tooLargeToSend.localizedDescription)
        #expect(self.outputs() == before)
        #expect(try Data(contentsOf: try #require(staged.url)) == stagedBytes)
    }

    @Test("the same send goes through when memory allows", .ambientTestKeyManager)
    func sameSendSucceedsWithMemory() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("guard-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let cm = try TestSupport.makeContactManager()
        let groupID = try makeGroup(cm)
        let vm = ComposeViewModel(
            recipient: .group(groupID), stagingKeyProvider: FixedStagingKey(), memoryGuard: guardReporting(Int.max / 8)
        )
        vm.setup(contactManager: cm)
        vm.messages = [try await stagedVideo(in: dir, using: vm)]

        await vm.encrypt(contactManager: cm)

        let out = try #require(vm.encryptedURL, "encrypt failed: \(vm.errorMessage)")
        try? FileManager.default.removeItem(at: out)
    }
}
