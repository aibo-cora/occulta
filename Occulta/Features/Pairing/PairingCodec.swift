//
//  PairingCodec.swift
//  Occulta
//
//  Turns a `PairingState` into the plaintext sealed into `Contact.Profile.Key.pairingEncrypted`, and back.
//
//  The plaintext is always exactly `capacity` bytes, in every state, so its sealed length says nothing about whether
//  a pairing has a secret (`bugs.md` Bug 196):
//  ```
//  [ formatVersion: 1 | present: 1 | secret: 32 | zeros to capacity ]
//  ```
//  `present` is 0 for no secret, 1 for a held one. The filler is inside the encryption, so zeros are as good as random.
//
//  A fixed layout, not a plist: it is a few bytes, and a plist would add a length nobody needs.
//  Modelled on `CardStateCodec`.
//

import Foundation

nonisolated
struct PairingCodec {

    static let capacity      = 128
    static let formatVersion: UInt8 = 0x01

    private static let secretRange = 2..<34

    enum CodecError: Error, Equatable {
        /// Not this format, or a field that can't be read.
        case malformed
        /// A secret that isn't 32 bytes. Nothing is padded or cut: a short one would be a bug upstream.
        case wrongSize
    }

    func encode(_ state: PairingState) throws -> Data {
        var plaintext = Data(count: Self.capacity)
        plaintext[0] = Self.formatVersion
        if let secret = state.secret {
            guard secret.count == Self.fieldSize else { throw CodecError.wrongSize }
            plaintext[1] = 1
            plaintext.replaceSubrange(Self.secretRange, with: secret)
        }
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> PairingState {
        guard plaintext.count == Self.capacity, plaintext.first == Self.formatVersion else { throw CodecError.malformed }

        let bytes = [UInt8](plaintext)
        switch bytes[1] {
        case 0: return .empty
        case 1: return .derived(secret: Data(bytes[Self.secretRange]))
        default: throw CodecError.malformed
        }
    }

    private static let fieldSize = 32
}
