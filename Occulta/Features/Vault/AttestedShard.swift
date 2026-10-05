//
//  AttestedShard.swift
//  Occulta
//

import Foundation
import OccultaCore

// MARK: - AttestedShard

/// A `.shard` attribute together with who delivered it.
///
/// Named for a mechanism this type no longer carries — it used to also hold a
/// trustee's attestation for the rotated-identity path; `bugs.md` Bug 125 removed
/// that field entirely, since it never verified content authenticity, only
/// sender identity, which the bundle's own transport already establishes.
/// Kept the name rather than renaming it as part of that change — a purely
/// cosmetic follow-up, not done here.
///
/// Threading `senderIdentifier` through storage is the load-bearing piece of
/// Bug 94 remedy 2: reconstruction counts *distinct senders*, not distinct
/// `SignedAttribute.id`s, so one identity cannot self-attest a whole group of
/// fabricated shares.
///
/// **This raises the floor to two senders, not to `threshold`.** The BEK restore
/// path cannot do better, and the reason is worth keeping: on the device that
/// needs it — one with no BEK of its own — the owner's chosen `threshold` does
/// not survive anywhere. It lives in the BEK payload's `ShardDistributionMetadata`,
/// which that device does not have, and it is not part of what a trustee is given,
/// so it cannot be recovered from them either. Reading it out of the `.occbak`
/// would be reading it from whoever authored the file. So the only floor left is
/// `ShamirSecretSharing.reconstruct`'s own `shares.count >= 2`. What actually gates
/// an unsolicited restore is the depth-0 confirmation in `OccultaApp`, not this
/// count. Do not build on this as if it were `threshold`-strength.
/// See `Docs/Features/Secure Mode/bugs.md`, Bug 94.
struct AttestedShard: Codable {
    /// The owner-signed shard. Verifies directly against the owner's current
    /// identity when unrotated (Branch A) — accepted either way once that check
    /// fails, `bugs.md` Bug 125.
    let attribute: SignedAttribute
    /// Who this shard arrived from, as resolved by the *receiving* device's own lookup —
    /// never sender-asserted. See `ShardCustodyManager.handleInbound`'s callers in
    /// `OccultaApp.swift`, where the sender identifier comes from
    /// `contactManager.openGroup(...)` resolving the decrypting key against the
    /// receiver's own contacts, not from anything the bundle's payload claims. Held as a
    /// tag of that identifier (`TrusteeTag`, `bugs.md` Bug 147).
    let sender: TrusteeTag
}
