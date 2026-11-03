//
//  PairingSecretCodec.swift
//  Occulta
//
//  Turns a `PairingSecretState` into the plaintext sealed into `Contact.Profile.Key.pairingSecretEncrypted`, and back.
//
//  The plaintext is always exactly `capacity` bytes, in every state, so its sealed length says nothing about whether
//  a pairing has a secret or how far it is (`bugs.md` Bug 196):
//  ```
//  [ formatVersion: 1 | phase: 1 | flags: 1 | secret: 32 | ourHalf: 32 | zeros to capacity ]
//  ```
//  `phase` is 0 none, 1 swapping, 2 held. `flags` bit 0 is `refusesOldForm`, bit 1 is `peerConfirmed`. A field a
//  phase doesn't use is zeros. The filler is inside the encryption, so zeros are as good as random.
//
//  A fixed layout, not a plist: it is a few bytes, and a plist would add a length nobody needs.
//  Modelled on `CardStateCodec`.
//

import Foundation

nonisolated
struct PairingSecretCodec {

    static let capacity      = 128
    static let formatVersion: UInt8 = 0x01

    private static let secretRange = 3..<35
    private static let halfRange   = 35..<67

    enum CodecError: Error, Equatable {
        /// Not this format, or a field that can't be read.
        case malformed
        /// A secret or half that isn't 32 bytes. Nothing is padded or cut: a short one would be a bug upstream.
        case wrongSize
    }

    func encode(_ state: PairingSecretState) throws -> Data {
        var plaintext = Data(count: Self.capacity)
        plaintext[0] = Self.formatVersion

        var flags: UInt8 = state.refusesOldForm ? 0x01 : 0x00
        switch state.phase {
        case .none:
            plaintext[1] = 0
        case .swapping(let ourHalf):
            plaintext[1] = 1
            guard ourHalf.count == Self.fieldSize else { throw CodecError.wrongSize }
            plaintext.replaceSubrange(Self.halfRange, with: ourHalf)
        case .held(let secret, let peerConfirmed):
            plaintext[1] = 2
            if peerConfirmed { flags |= 0x02 }
            guard secret.count == Self.fieldSize else { throw CodecError.wrongSize }
            plaintext.replaceSubrange(Self.secretRange, with: secret)
        }
        plaintext[2] = flags
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> PairingSecretState {
        guard plaintext.count == Self.capacity, plaintext.first == Self.formatVersion else { throw CodecError.malformed }

        let bytes = [UInt8](plaintext)
        let flags = bytes[2]
        guard flags & ~0x03 == 0 else { throw CodecError.malformed }
        let refusesOldForm = flags & 0x01 != 0
        let peerConfirmed  = flags & 0x02 != 0

        let phase: PairingSecretState.Phase
        switch bytes[1] {
        case 0:
            phase = .none
        case 1:
            phase = .swapping(ourHalf: Data(bytes[Self.halfRange]))
        case 2:
            phase = .held(secret: Data(bytes[Self.secretRange]), peerConfirmed: peerConfirmed)
        default:
            throw CodecError.malformed
        }
        return PairingSecretState(phase: phase, refusesOldForm: refusesOldForm)
    }

    private static let fieldSize = 32
}
