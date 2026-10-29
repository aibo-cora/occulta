//
//  ChallengeState.swift
//  Occulta
//
//  What a contact's `Contact.Profile.challengeStateEncrypted` holds: the identity-challenge state of that contact
//  at every depth, one fixed slot per depth (`bugs.md` Bug 180).
//

import Foundation

/// The challenge we issued to one contact and when we last verified them, for each depth a session can be at.
///
/// A session reads and writes the slot of its own depth and no other (`ContactManager+ChallengeLedger.swift`), so a
/// duress session finds an empty slot where the owner has state. The slot index is the depth, not a field inside a
/// shared slot: one shared slot would have to either refuse or overwrite when two depths challenge the same contact.
struct ChallengeState: Equatable {

    struct Slot: Equatable {
        /// The challenge issued at this depth and not yet settled. The context note is not kept: it stays in memory.
        var challenge: IdentityChallenge.OutstandingChallenge?
        /// Unix epoch seconds when this depth last verified the contact.
        var verifiedAt: UInt64?

        static let empty = Slot(challenge: nil, verifiedAt: nil)
    }

    /// Always `ChallengeStateCodec.slotCount` slots.
    private(set) var slots: [Slot]

    static let empty = ChallengeState(slots: Array(repeating: .empty, count: ChallengeStateCodec.slotCount))

    init(slots: [Slot]) {
        precondition(slots.count == ChallengeStateCodec.slotCount)
        self.slots = slots
    }

    /// The slot for `depth`, clamped into the slot range as `ChallengeStateCodec.slotIndex(forDepth:)` says.
    subscript(depth depth: Int) -> Slot {
        get { self.slots[ChallengeStateCodec.slotIndex(forDepth: depth)] }
        set { self.slots[ChallengeStateCodec.slotIndex(forDepth: depth)] = newValue }
    }

    /// Clears what has expired in every slot (the rule of `OutstandingChallenge.isExpired(at:)`, and the same for
    /// the verified-at time). Returns whether anything changed.
    mutating func removeExpired(now: Date) -> Bool {
        var changed = false
        for index in self.slots.indices {
            if let challenge = self.slots[index].challenge, challenge.isExpired(at: now) {
                self.slots[index].challenge = nil
                changed = true
            }
            if let at = self.slots[index].verifiedAt,
               abs(now.timeIntervalSince1970 - TimeInterval(at)) >= IdentityChallenge.timestampStaleThreshold {
                self.slots[index].verifiedAt = nil
                changed = true
            }
        }
        return changed
    }
}

/// Turns a `ChallengeState` into the plaintext sealed into `Contact.Profile.challengeStateEncrypted`, and back.
///
/// Fixed offsets, not a plist: it is 33 identical records, so every state is exactly `capacity` bytes by
/// construction, and its sealed length says nothing about whether a challenge was ever made or at what depth:
/// ```
/// header (16): formatVersion 1 | slotCount 1 | reserved 14 (zeros)
/// slot   (64): flags 1 | nonce 32 | issuedAt UInt64 BE 8 | verifiedAt UInt64 BE 8 | zeros 15
///              flags bit 0 = a challenge is outstanding, bit 1 = verified-at is set
/// ```
/// Slot `d` is depth `d`. The slot count is a constant of this format, not of `AppLayerConfig.maxDepthCount`: raising
/// the latter must not change the length of rewritten rows and divide the population by length (Bug 85), so a test
/// fails if `slotCount` falls below `maxDepthCount + 1`, and raising it then needs a migration of every row.
///
/// Lossless and total: nothing can overflow. A depth above the last slot is clamped into it, which cannot happen
/// (the deepest reachable depth is 32). Padding is inside the encryption, so zeros are as good as random.
struct ChallengeStateCodec {

    static let slotCount     = 33
    static let formatVersion: UInt8 = 0x01
    static let headerSize    = 16
    static let slotSize      = 64
    static let capacity      = headerSize + slotCount * slotSize

    private static let outstandingFlag: UInt8 = 0b01
    private static let verifiedFlag:    UInt8 = 0b10

    enum CodecError: Error, Equatable {
        /// Not this format, or a field that can't be read.
        case malformed
    }

    static func slotIndex(forDepth depth: Int) -> Int {
        min(max(depth, 0), self.slotCount - 1)
    }

    func encode(_ state: ChallengeState) throws -> Data {
        var plaintext = Data(capacity: Self.capacity)
        plaintext.append(Self.formatVersion)
        plaintext.append(UInt8(Self.slotCount))
        plaintext.append(Data(count: Self.headerSize - plaintext.count))

        for slot in state.slots {
            var record = Data(capacity: Self.slotSize)
            var flags: UInt8 = 0
            if slot.challenge != nil  { flags |= Self.outstandingFlag }
            if slot.verifiedAt != nil { flags |= Self.verifiedFlag }
            record.append(flags)

            if let challenge = slot.challenge {
                guard challenge.nonce.count == IdentityChallenge.nonceLength else { throw CodecError.malformed }
                record.append(challenge.nonce)
            } else {
                record.append(Data(count: IdentityChallenge.nonceLength))
            }
            withUnsafeBytes(of: (slot.challenge?.issuedAt ?? 0).bigEndian) { record.append(contentsOf: $0) }
            withUnsafeBytes(of: (slot.verifiedAt ?? 0).bigEndian) { record.append(contentsOf: $0) }
            record.append(Data(count: Self.slotSize - record.count))
            plaintext.append(record)
        }
        return plaintext
    }

    func decode(_ plaintext: Data) throws -> ChallengeState {
        guard
            plaintext.count == Self.capacity,
            plaintext.first == Self.formatVersion,
            plaintext[plaintext.startIndex + 1] == UInt8(Self.slotCount)
        else { throw CodecError.malformed }

        let bytes = [UInt8](plaintext)
        let nonceEnd = 1 + IdentityChallenge.nonceLength
        var slots: [ChallengeState.Slot] = []

        for index in 0..<Self.slotCount {
            let start = Self.headerSize + index * Self.slotSize
            let flags = bytes[start]
            guard flags & ~(Self.outstandingFlag | Self.verifiedFlag) == 0 else { throw CodecError.malformed }

            let nonce      = Data(bytes[start + 1 ..< start + nonceEnd])
            let issuedAt   = Self.readUInt64(bytes, at: start + nonceEnd)
            let verifiedAt = Self.readUInt64(bytes, at: start + nonceEnd + 8)

            slots.append(ChallengeState.Slot(
                challenge:  flags & Self.outstandingFlag != 0 ? .init(nonce: nonce, issuedAt: issuedAt) : nil,
                verifiedAt: flags & Self.verifiedFlag != 0 ? verifiedAt : nil
            ))
        }
        return ChallengeState(slots: slots)
    }

    private static func readUInt64(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        bytes[offset ..< offset + 8].reduce(0) { ($0 << 8) | UInt64($1) }
    }
}
