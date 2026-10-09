//
//  Contact+Model+Prekeys.swift
//  Occulta
//
//  Created by Yura on 3/17/26.
//

import Foundation
import OccultaCore

// MARK: - Sender identification on Contact.Profile
//
// Prekeys are ContactManager's to read and write (`Contact+Manager+Prekeys.swift`).

extension Contact.Profile {
    /// SHA-256(contactPublicKey || bundle.fingerprintNonce) == bundle.senderFingerprint.
    /// O(1) per contact — no trial ECDH.
    func isLikelySender(of bundle: OccultaBundle, contactPublicKey: Data) -> Bool {
        let candidate = OccultaBundle.SecrecyContext.fingerprint(for: contactPublicKey, nonce: bundle.fingerprintNonce)
        
        return candidate == bundle.senderFingerprint
    }
}
