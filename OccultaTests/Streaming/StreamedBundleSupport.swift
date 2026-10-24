//
//  StreamedBundleSupport.swift
//  OccultaTests
//
//  A streamed bundle written to disk the way a sender will write one (STREAMING_SPEC §8.3), from the pieces
//  production has now: the codec, the group seal's slot wrapping, and `NoCacheFile`. The receive tests open
//  these through the real receive path.
//

import Testing
import CryptoKit
import Foundation
import SwiftData
@testable import Occulta
@testable import OccultaFormats

/// Deterministic bytes, so a failure reproduces and a marker survives the scan for plaintext on disk.
func streamedPattern(_ count: Int, seed: UInt8 = 1) -> Data {
    var state = UInt32(seed) &* 2_654_435_761 | 1
    return Data((0..<count).map { _ in
        state = state &* 1_664_525 &+ 1_013_904_223
        return UInt8(truncatingIfNeeded: state >> 24)
    })
}

/// A streamed file's entry: the basket file and the bytes that travel in the stream.
func streamedEntry(_ name: String, _ data: Data, ext: String = "bin") -> (file: OccultaFormats.File, streamed: Data?) {
    (OccultaFormats.File(format: .file(.init(name: name, extension: ext)), date: Date(timeIntervalSinceReferenceDate: 10)), data)
}

func inlineTextEntry(_ text: String) -> (file: OccultaFormats.File, streamed: Data?) {
    (OccultaFormats.File(content: Data(text.utf8), format: .text, date: Date(timeIntervalSinceReferenceDate: 5)), nil)
}

struct WrittenBundle {
    let url: URL
    /// The envelope: header and group, an empty `ciphertext`.
    let bundle: OccultaBundle
    let sessionKey: SymmetricKey
}

/// Writes a streamed group bundle from `sender` to `recipients` at `url`.
///
/// `declaredLengths` lets a test have the manifest say something other than what the stream holds.
@MainActor
func writeStreamedBundle(
    to url: URL,
    from sender: TestKeyManager,
    recipients: [GroupRecipient],
    files: [(file: OccultaFormats.File, streamed: Data?)],
    appVersion: String? = "2.0.0",
    groupID: UUID = UUID(),
    declaredLengths: [UInt64?]? = nil
) throws -> WrittenBundle {
    let crypto         = Manager.Crypto(keyManager: sender)
    let sessionKey     = SymmetricKey(size: .bits256)
    let sessionKeyData = sessionKey.withUnsafeBytes { Data($0) }
    let senderPublicKey = try sender.retrieveIdentity()

    let blindNonce = try OccultaBundle.SecrecyContext.generateNonce()
    let blind = Data(HMAC<SHA256>.authenticationCode(
        for: blindNonce, using: SymmetricKey(data: withUnsafeBytes(of: groupID.uuid) { Data($0) })
    ))
    let outerSecrecy = OccultaBundle.SecrecyContext(mode: .group, ephemeralPublicKey: Data(), prekeyID: nil)
    let outerNonce = try OccultaBundle.SecrecyContext.generateNonce()

    // The manifest, framed, and the plaintext stream it opens.
    let payload = OccultaBundle.SealedPayload(
        message: try WireHandle.encode(
            basket: Basket(files: files.map(\.file), date: Date(timeIntervalSinceReferenceDate: 0)),
            streamedLengths: declaredLengths ?? files.map { $0.streamed.map { UInt64($0.count) } }
        ),
        appVersion: appVersion,
        senderProof: Data(HMAC<SHA256>.authenticationCode(for: senderPublicKey, using: sessionKey)),
        groupID: groupID
    )
    let framed  = try BodyStream.Manifest.frame(payload: payload)
    let streams = files.compactMap(\.streamed)
    let layout  = try BodyStream.Layout(plaintextLength: UInt64(framed.count + streams.reduce(0) { $0 + $1.count }))

    // The header first: it names T. The slots need the digest, so they and the sections come last.
    let headerOnly = OccultaBundle(
        version: .streamedBodyCapable, secrecy: outerSecrecy, ciphertext: Data(), fingerprintNonce: outerNonce,
        senderFingerprint: OccultaBundle.SecrecyContext.fingerprint(for: senderPublicKey, nonce: outerNonce)
    )
    let writer = try NoCacheFile.writer(url)
    try writer.write(try WireHandle.encodeHeader(headerOnly, ciphertextLength: layout.streamLength))

    var sealer = BodyStream.Sealer(
        sessionKey: sessionKey, header: try BodyStream.headerAAD(secrecy: outerSecrecy, blind: blind), layout: layout
    )
    try sealer.append(framed) { try writer.write($0) }
    for data in streams { try sealer.append(data) { try writer.write($0) } }
    let digest = try sealer.finish { try writer.write($0) }

    let bundle = OccultaBundle(
        version: .streamedBodyCapable, secrecy: outerSecrecy, ciphertext: Data(), fingerprintNonce: outerNonce,
        senderFingerprint: headerOnly.senderFingerprint,
        group: OccultaBundle.GroupEnvelope(
            blind: blind, blindNonce: blindNonce,
            recipients: try recipients.map {
                try crypto.wrapRecipient($0, sessionKeyData: sessionKeyData, blind: blind, bodyDigest: digest)
            }
        )
    )
    try writer.write(try WireHandle.encodeSections(bundle))
    try writer.finish()
    return WrittenBundle(url: url, bundle: bundle, sessionKey: sessionKey)
}

/// `publicKey` as a contact on this device. A pending batch of ours stands waiting for them, so a bundle from
/// them generates no new one, which would need an Enclave.
@MainActor
func insertStreamedSender(identifier: String, publicKey: Data, in contactManager: ContactManager) throws {
    let profile = Contact.Profile(
        identifier: identifier, givenName: "", familyName: "", middleName: "",
        nickname: "", organizationName: "", departmentName: "", jobTitle: ""
    )
    profile.contactPublicKeys = [Contact.Profile.Key(
        material: try Manager.Crypto().encrypt(data: publicKey), owner: Data(), date: Data(),
        quantumKeyMaterialEncrypted: nil
    )]
    var record = PrekeyRecord.empty
    record.ownBatches = [PrekeyRecord.OwnBatch(
        id: Data((0..<16).map { _ in .random(in: .min ... .max) }), createdAt: Date(), retiredAt: nil, isPending: true,
        keys: [PrekeyRecord.OwnKey(id: withUnsafeBytes(of: UUID().uuid) { Data($0) }, blob: nil,
                                   publicKey: try TestKeyManager().retrieveIdentity())]
    )]
    profile.prekeyRecordEncrypted = try PrekeyRecordCodec().encode(record).encrypt()
    try contactManager.insertProfile(profile)
}

func streamedScratchDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("streamed-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}
