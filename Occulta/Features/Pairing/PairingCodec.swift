//
//  PairingCodec.swift
//  Occulta
//
//  Turns a `PairingState` into the plaintext sealed into `Contact.Profile.Key.pairingEncrypted`, and back.
//
//  The plaintext is always exactly `capacity` bytes, in every state, so its sealed length says nothing about whether a
//  pairing has a routing key and pair keys (`bugs.md` Bug 196). The fields sit at fixed offsets, each blob in a
//  fixed-size room with its length in front:
//  ```
//  [ version 1 | present 1 | routingKey 32
//  | agreement blob: length 2, room 256 | signing blob: length 2, room 256
//  | our agreement key 65 | our signing key 65 | peer agreement key 65 | peer signing key 65
//  | ML-DSA blob: length 2, room 12288 | peer ML-DSA key: present 1, 2592
//  | zeros to capacity ]
//  ```
//  `present` is 0 for neither, 1 for a routing key with pair keys. A field a state doesn't use is zeros. The filler is inside the encryption, so zeros are as good as random. A blob too large for its
//  room is refused, never cut: the room is the measured size with headroom (143 bytes for a P-256 Enclave blob and 7,540
//  for ML-DSA-87 on the Simulator).
//
//  A fixed layout, not a plist: a length would otherwise vary with what is held. Modelled on `CardStateCodec`.
//

import Foundation
import OccultaFormats

nonisolated
struct PairingCodec {

    /// 16 KiB: the layout above ends at byte 15,693, which leaves room for a field a later release adds.
    static let capacity      = 16_384
    static let formatVersion: UInt8 = 0x02

    static let p256BlobRoom  = 256
    static let mldsaBlobRoom = 12_288
    static let mldsaKeySize  = 2_592
    private static let keySize = 65

    // Offsets.
    private static let routingKeyAt = 2
    private static let agreementBlobAt = 34
    private static let signingBlobAt = agreementBlobAt + 2 + p256BlobRoom
    private static let ourAgreementKeyAt = signingBlobAt + 2 + p256BlobRoom
    private static let ourSigningKeyAt = ourAgreementKeyAt + keySize
    private static let peerAgreementKeyAt = ourSigningKeyAt + keySize
    private static let peerSigningKeyAt = peerAgreementKeyAt + keySize
    private static let mldsaBlobAt = peerSigningKeyAt + keySize
    private static let peerMLDSAAt = mldsaBlobAt + 2 + mldsaBlobRoom
    private static let end = peerMLDSAAt + 1 + mldsaKeySize

    enum CodecError: Error, Equatable {
        /// Not this format, or a field that can't be read.
        case malformed
        /// A key or blob that doesn't fit its room, or isn't its size. Nothing is padded or cut: it would be a bug upstream.
        case wrongSize
    }

    func encode(_ state: PairingState) throws -> Data {
        var plaintext = Data(count: Self.capacity)
        plaintext[0] = Self.formatVersion

        guard let routingKey = state.routingKey, let keys = state.keys else { return plaintext }
        guard routingKey.count == RoutingKey.size else { throw CodecError.wrongSize }
        plaintext[1] = 1
        plaintext.replaceSubrange(Self.routingKeyAt..<(Self.routingKeyAt + 32), with: routingKey)

        try Self.put(keys.ourAgreementBlob, room: Self.p256BlobRoom, at: Self.agreementBlobAt, in: &plaintext, mustBeNonEmpty: true)
        try Self.put(keys.ourSigningBlob, room: Self.p256BlobRoom, at: Self.signingBlobAt, in: &plaintext, mustBeNonEmpty: true)
        try Self.putKey(keys.ourAgreementKey, at: Self.ourAgreementKeyAt, in: &plaintext)
        try Self.putKey(keys.ourSigningKey, at: Self.ourSigningKeyAt, in: &plaintext)
        try Self.putKey(keys.peerAgreementKey, at: Self.peerAgreementKeyAt, in: &plaintext)
        try Self.putKey(keys.peerSigningKey, at: Self.peerSigningKeyAt, in: &plaintext)
        if let blob = keys.ourMLDSABlob {
            try Self.put(blob, room: Self.mldsaBlobRoom, at: Self.mldsaBlobAt, in: &plaintext, mustBeNonEmpty: true)
        }
        if let peerKey = keys.peerMLDSAKey {
            guard peerKey.count == Self.mldsaKeySize else { throw CodecError.wrongSize }
            plaintext[Self.peerMLDSAAt] = 1
            plaintext.replaceSubrange((Self.peerMLDSAAt + 1)..<Self.end, with: peerKey)
        }
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> PairingState {
        guard plaintext.count == Self.capacity, plaintext.first == Self.formatVersion else { throw CodecError.malformed }
        let bytes = [UInt8](plaintext)

        switch bytes[1] {
        case 0:
            return .empty
        case 1:
            let routingKey = Data(bytes[Self.routingKeyAt..<(Self.routingKeyAt + 32)])
            let agreementBlob = try Self.get(bytes, room: Self.p256BlobRoom, at: Self.agreementBlobAt)
            let signingBlob = try Self.get(bytes, room: Self.p256BlobRoom, at: Self.signingBlobAt)
            guard !agreementBlob.isEmpty, !signingBlob.isEmpty else { throw CodecError.malformed }
            let mldsaBlob = try Self.get(bytes, room: Self.mldsaBlobRoom, at: Self.mldsaBlobAt)
            let peerMLDSA: Data?
            switch bytes[Self.peerMLDSAAt] {
            case 0: peerMLDSA = nil
            case 1: peerMLDSA = Data(bytes[(Self.peerMLDSAAt + 1)..<Self.end])
            default: throw CodecError.malformed
            }
            return .paired(routingKey: routingKey, keys: PairKeys(
                ourAgreementBlob: agreementBlob, ourAgreementKey: Data(bytes[Self.ourAgreementKeyAt..<(Self.ourAgreementKeyAt + Self.keySize)]),
                ourSigningBlob: signingBlob, ourSigningKey: Data(bytes[Self.ourSigningKeyAt..<(Self.ourSigningKeyAt + Self.keySize)]),
                peerAgreementKey: Data(bytes[Self.peerAgreementKeyAt..<(Self.peerAgreementKeyAt + Self.keySize)]),
                peerSigningKey: Data(bytes[Self.peerSigningKeyAt..<(Self.peerSigningKeyAt + Self.keySize)]),
                ourMLDSABlob: mldsaBlob.isEmpty ? nil : mldsaBlob, peerMLDSAKey: peerMLDSA
            ))
        default:
            throw CodecError.malformed
        }
    }

    // MARK: - Fields

    private static func put(_ blob: Data, room: Int, at offset: Int, in plaintext: inout Data, mustBeNonEmpty: Bool) throws {
        guard blob.count <= room, !(mustBeNonEmpty && blob.isEmpty) else { throw CodecError.wrongSize }
        plaintext[offset] = UInt8(blob.count >> 8)
        plaintext[offset + 1] = UInt8(blob.count & 0xFF)
        plaintext.replaceSubrange((offset + 2)..<(offset + 2 + blob.count), with: blob)
    }

    private static func putKey(_ key: Data, at offset: Int, in plaintext: inout Data) throws {
        guard key.count == Self.keySize else { throw CodecError.wrongSize }
        plaintext.replaceSubrange(offset..<(offset + Self.keySize), with: key)
    }

    private static func get(_ bytes: [UInt8], room: Int, at offset: Int) throws -> Data {
        let length = Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
        guard length <= room else { throw CodecError.malformed }
        return Data(bytes[(offset + 2)..<(offset + 2 + length)])
    }
}
