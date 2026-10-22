//
//  CardStateCodec.swift
//  Occulta
//

import Foundation

/// Turns a `CardState` into the plaintext sealed into `Contact.Profile.introductionCardEncrypted`, and back.
///
/// The plaintext is always exactly `capacity` bytes, in every state, so its sealed length says nothing about
/// whether a contact has a card or what kind (`Docs/Features/Introduction Cards/SPEC.md` §5):
/// ```
/// [ formatVersion: 1 byte | payload length: UInt32 big-endian | payload: binary plist | zeros to capacity ]
/// ```
/// The filler is inside the encryption, so zeros are as good as random.
///
/// Lossless: a state too large for `capacity` throws rather than being trimmed. `capacity` is set by a size
/// test on the largest state (`.imported`, with distinct values everywhere), not by design.
///
/// Modelled on `PrekeyRecordCodec`.
nonisolated
struct CardStateCodec {

    static let capacity      = 12 * 1024
    static let formatVersion: UInt8 = 0x01
    static let headerSize    = 5

    enum CodecError: Error, Equatable {
        /// The encoded state doesn't fit `capacity`.
        case overCapacity
        /// Not this format, or a field that can't be read.
        case malformed
    }

    func encode(_ state: CardState) throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let payload = try encoder.encode(state)
        guard Self.headerSize + payload.count <= Self.capacity else { throw CodecError.overCapacity }

        var plaintext = Data(capacity: Self.capacity)
        plaintext.append(Self.formatVersion)
        withUnsafeBytes(of: UInt32(payload.count).bigEndian) { plaintext.append(contentsOf: $0) }
        plaintext.append(payload)
        plaintext.append(Data(count: Self.capacity - plaintext.count))
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> CardState {
        guard plaintext.count == Self.capacity, plaintext.first == Self.formatVersion else { throw CodecError.malformed }

        let bytes  = [UInt8](plaintext)
        let length = bytes[1...4].reduce(0) { ($0 << 8) | Int($1) }
        guard length <= Self.capacity - Self.headerSize else { throw CodecError.malformed }

        let payload = Data(bytes[Self.headerSize ..< Self.headerSize + length])
        do {
            return try PropertyListDecoder().decode(CardState.self, from: payload)
        } catch {
            throw CodecError.malformed
        }
    }
}
