//
//  PairingCapabilities.swift
//  Occulta
//
//  What a contact's current pairing holds, for the upgrade icon in the contact list and the three rows in the detail view
//  (`bugs.md` Bug 196). Read live from the contact's own sealed key row each time it is drawn, and stored nowhere: no
//  "seen" or "dismissed" state, no write, and the same code at every depth. A contact hidden at the current depth is
//  never read by another contact's row.
//
//  The rows say what a pairing lacks and what it needs, and nothing about safety: a pairing made before pair keys is
//  exactly as safe as it was.
//

import Foundation
import CryptoKit
import OccultaFormats
import OccultaCore

nonisolated
struct PairingCapabilities: Equatable {

    /// The pairing has a key pair of its own.
    var pairKeys: Bool
    /// The exchange was hybrid: an ML-KEM secret protects the key agreement.
    var postQuantumAgreement: Bool
    /// Both phones made an ML-DSA key at the exchange. Nothing signs with it yet, so it never drives the icon.
    var postQuantumSignatures: Bool
    /// The contact's recorded tier says their build understands pair-key pairings, so a re-exchange would give one.
    var peerCanPair: Bool

    /// Whether to offer an upgrade: the pairing has no pair keys and the contact's build could give it some. A contact on
    /// an older build shows nothing here, where a re-exchange could not help.
    var upgradeAvailable: Bool { !self.pairKeys && self.peerCanPair }

    static let none = PairingCapabilities(pairKeys: false, postQuantumAgreement: false, postQuantumSignatures: false, peerCanPair: false)

    /// What exchanging keys again in person would add to this pairing: the only way a pairing gets either one, since nothing
    /// is swapped in band.
    enum Upgrade: Equatable {
        /// Pair keys, and with them the routing key: 2.0.1 gave them to new pairings only.
        case pairKeys
        /// ML-KEM, which needs iOS 26 on both phones.
        case postQuantum
        case both

        /// The line shown above the link to the exchange. Plain words: what a re-exchange adds, and nothing about risk.
        var prompt: String {
            switch self {
            case .pairKeys:
                "Exchange keys again in person to give this pairing pair keys."
            case .postQuantum:
                "Exchange keys again in person, with both phones on iOS 26 or later, to add quantum-resistant key agreement."
            case .both:
                "Exchange keys again in person to add pair keys and, with both phones on iOS 26 or later, quantum-resistant key agreement."
            }
        }
    }

    /// What a re-exchange could add, or nil when the pairing has both or a re-exchange could not help. Computed from this
    /// pairing and this phone alone, so a contact reads the same at every depth.
    ///
    /// - A contact whose recorded build predates pair keys, or was never heard from, and whose pairing has none, offers
    ///   nothing: it could not make them.
    /// - ML-KEM is offered only where this phone can make it. A pairing with pair keys has a 2.0.1 peer by construction.
    func upgrade(thisPhoneCanPostQuantum: Bool = PostQuantumProviderFactory.create() != nil) -> Upgrade? {
        guard self.pairKeys || self.peerCanPair else { return nil }

        switch (!self.pairKeys, !self.postQuantumAgreement && thisPhoneCanPostQuantum) {
        case (true, true):   return .both
        case (true, false):  return .pairKeys
        case (false, true):  return .postQuantum
        case (false, false): return nil
        }
    }
}

extension Contact.Profile {

    /// The capabilities of the current pairing, or `.none` for a contact with no current key (a card contact or one still
    /// waiting for an exchange), which has nothing to upgrade.
    var pairingCapabilities: PairingCapabilities {
        self.pairingCapabilities(
            opening: { $0.decrypt() },
            bundleVersion: { ContactManager.bundleVersionState(for: self, using: Manager.Crypto()) }
        )
    }

    /// Same as `pairingCapabilities`, under a local DB key the caller already derived, for a screen that reads
    /// several fields in one pass.
    func pairingCapabilities(using key: SymmetricKey) -> PairingCapabilities {
        self.pairingCapabilities(
            opening: { $0.decrypt(using: key) },
            bundleVersion: { ContactManager.bundleVersionState(for: self, using: key) }
        )
    }

    private func pairingCapabilities(
        opening open: (Data) -> Data?,
        bundleVersion: () -> ContactManager.BundleVersionState
    ) -> PairingCapabilities {
        guard let key = self.currentKey else { return .none }

        let state: PairingState = key.pairingEncrypted
            .flatMap { open($0) }
            .flatMap { try? PairingCodec().decode($0) } ?? .empty
        let peerCanPair: Bool = {
            guard case .readable(let version) = bundleVersion() else { return false }
            return version.isAtLeast(.pairingCapable)
        }()

        return PairingCapabilities(
            pairKeys: state.keys != nil,
            postQuantumAgreement: key.quantumKeyMaterialEncrypted != nil,
            postQuantumSignatures: state.keys.map { $0.ourMLDSABlob != nil && $0.peerMLDSAKey != nil } ?? false,
            peerCanPair: peerCanPair
        )
    }
}
