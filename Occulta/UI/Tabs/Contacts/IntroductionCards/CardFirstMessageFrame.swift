//
//  CardFirstMessageFrame.swift
//  Occulta
//
//  The read view for the first messages on Bob's card (W-08, `Docs/Features/Introduction Cards/FINDINGS.md`):
//  who wrote them can't be known until Bob verifies in person, so the message opens with that said above it, the
//  Standard Encryption label under it, and the trust line below. Any other sender's message is shown unchanged.
//
//  The same at every depth, and nothing on it leads into the contact (decided 2026-10-19). A card message can
//  open at a duress depth, since redemption runs at every depth; anything that differed there would tell a
//  coercer the depth, and a way into a hidden contact would let them act on it. Bob replies from the contact's
//  details, where W-08 also stands while the bootstrap is open.
//

import SwiftUI
import SwiftData

struct CardFirstMessageFrame<Content: View>: View {
    /// The identifier of the contact the message came from.
    let owner: String
    @ViewBuilder let content: Content

    @Query private var contacts: [Contact.Profile]

    /// The sender's first name, set only when the sender is on Bob's side of a card whose bootstrap is still open.
    @State private var name: String?

    init(owner: String, @ViewBuilder content: () -> Content) {
        self.owner   = owner
        self.content = content()
        self._contacts = Query(filter: #Predicate { $0.identifier == owner })
    }

    var body: some View {
        SwiftUI.Group {
            if let name = self.name {
                VStack(spacing: 12) {
                    CardNotice(tone: .warn, IntroCardCopy.firstMessage(name: name))
                        .padding(.horizontal, 16)
                        .padding(.top, 8)

                    // Sealed to the card key, as compose labelled it on Carol's phone (SPEC §4.3).
                    SecrecyIndicator(secrecy: .longTerm, name: name, standard: true)
                        .padding(.horizontal, 16)

                    self.content
                }
                .safeAreaInset(edge: .bottom) {
                    CardNotice(tone: .warn, IntroCardCopy.trustLine)
                        .padding(16)
                        .background(.bar)
                }
            } else {
                self.content
            }
        }
        // Read once: the state is the sender's card field, and it can't change while the message is open.
        .task(id: self.owner) {
            guard
                let contact = self.contacts.first,
                case .conversation(_, _, _, _, _, let bootstrapOpen, let isIssuer) = contact.cardState,
                bootstrapOpen, isIssuer
            else { return }
            self.name = IntroCardCopy.firstName(of: contact.givenName.decrypt())
        }
    }
}
