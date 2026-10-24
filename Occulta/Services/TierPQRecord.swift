//
//  TierPQRecord.swift
//  Occulta
//
//  The Keychain record of one access tier's Enclave ML-KEM-1024 key: term 3 of the Bug 171 derivations
//  (`Docs/Features/Secure Mode/bugs.md`, `Docs/General/decisions.md`). One record per tier, a generic-password
//  item, `WhenUnlockedThisDeviceOnly`: U (device unlock, app), B (the vault) and S (share staging, in the shared
//  group, with its own copy of this codec in `ShareStagingKeyManager.swift`: the extension links only that file).
//
//  The record says which form the tier's keys take. On iOS 26+ it is *hybrid*: the Enclave key's blob and a
//  ciphertext c encapsulated to its public key, so each use decapsulates c inside the Enclave and mixes the
//  32-byte result ss into the key (`HKDF(t ‖ ss ‖ r)`). Below iOS 26 it is *classical*: no key, and the key is
//  `HKDF(t ‖ r)`. Both are the same size, so every install holds the same items at the same sizes, and the mode
//  byte is readable only by whoever reads the item.
//
//  Layout, `size` bytes always:
//
//      byte 0                mode        0 = classical, 1 = hybrid
//      byte 1-2              blob length UInt16 big-endian             (hybrid only)
//      byte 3 ..< 3 + 8192   blob        the Enclave key's `dataRepresentation`, then random padding (hybrid only)
//      the last 1568 bytes   c           the ML-KEM-1024 ciphertext    (hybrid only)
//
//  In a classical record everything after the mode byte is random.
//
//  The mode only moves forward, from classical to hybrid, and only through the upgrade pass of a device that
//  reaches iOS 26. A hybrid record whose blob won't decapsulate is a failure, never a fallback to classical.
//

import Foundation
import Security

nonisolated struct TierPQRecord: Equatable {

    enum Mode: UInt8 {
        case classical = 0
        case hybrid    = 1
    }

    enum CodecError: Error, Equatable {
        /// The key's blob is empty or longer than `blobCapacity`. Never truncated: a truncated blob is a lost key.
        case blobSize(Int)
        /// The ciphertext isn't `ciphertextSize` bytes: not an ML-KEM-1024 ciphertext.
        case ciphertextSize(Int)
        case entropyUnavailable
    }

    /// Room for the Enclave key's `dataRepresentation`.
    ///
    /// Measured on the iPhone 17 Pro Simulator (iOS 26.1), 25 keys made with `PostQuantumProviderFactory.create()`:
    /// every blob is 4,788 bytes, which matches `Docs/Features/Introduction Cards/SPEC.md` §5. The blob carries the
    /// 1,568-byte public key. 8,192 is 1.7 times that: room for a larger blob on a device (the Simulator's number is
    /// not a device's), or in a later OS, without changing the record's size. A blob that still doesn't fit throws at
    /// creation; it is never cut. The padding is random, so the size is not a signal.
    static let blobCapacity = 8192

    /// An ML-KEM-1024 ciphertext, and the public key it is made to.
    static let ciphertextSize = 1568

    static let lengthFieldSize = 2

    /// 1 + 2 + 8192 + 1568 = 9,763 bytes, whichever the mode.
    static let size = 1 + Self.lengthFieldSize + Self.blobCapacity + Self.ciphertextSize

    let mode: Mode

    /// The Enclave key's blob. Empty in a classical record.
    let keyBlob: Data

    /// The ML-KEM ciphertext c. Empty in a classical record.
    let ciphertext: Data

    /// The classical record: no key, no ciphertext.
    static let classical = TierPQRecord(mode: .classical, keyBlob: Data(), ciphertext: Data())

    private init(mode: Mode, keyBlob: Data, ciphertext: Data) {
        self.mode       = mode
        self.keyBlob    = keyBlob
        self.ciphertext = ciphertext
    }

    /// A hybrid record. Throws if the blob doesn't fit or the ciphertext isn't an ML-KEM-1024 one.
    static func hybrid(keyBlob: Data, ciphertext: Data) throws -> TierPQRecord {
        guard !keyBlob.isEmpty, keyBlob.count <= Self.blobCapacity else { throw CodecError.blobSize(keyBlob.count) }
        guard ciphertext.count == Self.ciphertextSize else { throw CodecError.ciphertextSize(ciphertext.count) }

        return TierPQRecord(mode: .hybrid, keyBlob: keyBlob, ciphertext: ciphertext)
    }

    /// The bytes to store: `size` of them, with random bytes wherever the record has nothing.
    func encoded() throws -> Data {
        var out = Data(capacity: Self.size)
        out.append(self.mode.rawValue)

        switch self.mode {
        case .classical:
            out.append(try Self.randomBytes(Self.size - 1))

        case .hybrid:
            var length = UInt16(self.keyBlob.count).bigEndian
            withUnsafeBytes(of: &length) { out.append(contentsOf: $0) }
            out.append(self.keyBlob)
            out.append(try Self.randomBytes(Self.blobCapacity - self.keyBlob.count))
            out.append(self.ciphertext)
        }

        return out
    }

    /// nil unless `data` is exactly `size` bytes with a known mode byte and, for a hybrid record, a plausible blob
    /// length. Nothing in a classical record after the mode byte is read.
    init?(decoding data: Data) {
        guard data.count == Self.size, let first = data.first, let mode = Mode(rawValue: first) else { return nil }

        switch mode {
        case .classical:
            self.init(mode: .classical, keyBlob: Data(), ciphertext: Data())

        case .hybrid:
            let bytes  = [UInt8](data)
            let length = Int(bytes[1]) << 8 | Int(bytes[2])
            guard length > 0, length <= Self.blobCapacity else { return nil }

            let blobStart = 1 + Self.lengthFieldSize
            self.init(
                mode:       .hybrid,
                keyBlob:    Data(bytes[blobStart..<(blobStart + length)]),
                ciphertext: Data(bytes[(Self.size - Self.ciphertextSize)...])
            )
        }
    }

    private static func randomBytes(_ count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw CodecError.entropyUnavailable
        }
        return Data(bytes)
    }
}
