//
//  PairingCapabilitySection.swift
//  Occulta
//
//  The three rows the detail view shows for a contact's pairing, and the glyph the list shows (`bugs.md` Bug 196). They read
//  `Contact.Profile.pairingCapabilities`, which is computed from the contact's own row each time and stored nowhere.
//

import SwiftUI

/// The upgrade glyph in the contact list: neutral, not a warning. Shown only when a re-exchange would give the pairing pair keys.
struct PairingUpgradeGlyph: View {
    let capabilities: PairingCapabilities

    var body: some View {
        if self.capabilities.upgradeAvailable {
            Image(systemName: "arrow.up.circle")
                .font(.system(size: 15, weight: .regular))
                .foregroundStyle(.secondary)
                .accessibilityLabel("Re-exchange in person to upgrade this contact")
        }
    }
}

/// What the pairing holds and what each thing is for. Present or missing, in plain words, with no word about safety.
struct PairingCapabilityRows: View {
    let identifier: String
    let capabilities: PairingCapabilities

    var body: some View {
        VStack(spacing: 0) {
            self.row(
                title: "Pair keys", present: self.capabilities.pairKeys,
                explanation: self.capabilities.pairKeys
                    ? "A key made only for this contact."
                    : "A key made only for this contact. Without it, files between you are tied to your device's main key, which every contact you've paired with holds."
            )
            Divider().padding(.leading, 14)
            self.row(
                title: "Quantum-resistant key agreement", present: self.capabilities.postQuantumAgreement,
                explanation: self.capabilities.postQuantumAgreement
                    ? "Keeps recorded messages unreadable even to a future quantum computer."
                    : "Keeps recorded messages unreadable even to a future quantum computer. Needs iOS 26 on both phones."
            )
            Divider().padding(.leading, 14)
            self.row(
                title: "Quantum-resistant signatures", present: self.capabilities.postQuantumSignatures,
                explanation: "Prepared for a future update. Not used yet."
            )

            if self.capabilities.upgradeAvailable {
                NavigationLink {
                    KeyExchange(identifier: self.identifier)
                } label: {
                    Text("Re-exchange in person to upgrade")
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 8)
            }
        }
    }

    private func row(title: String, present: Bool, explanation: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Image(systemName: present ? "checkmark.circle" : "circle.dashed")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                Spacer()
                Text(present ? "Yes" : "Not yet")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Text(explanation)
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}
