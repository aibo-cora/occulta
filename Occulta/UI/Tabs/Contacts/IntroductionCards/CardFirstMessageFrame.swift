//
//  CardFirstMessageFrame.swift
//  Occulta
//
//  The read view for the first messages on Bob's card (W-08, `Docs/Features/Introduction Cards/FINDINGS.md`):
//  who wrote them can't be known until Bob verifies in person, so the message opens with that said above it,
//  the trust line and a way to answer below it. Any other sender's message is shown unchanged.
//

import SwiftUI
import SwiftData

struct CardFirstMessageFrame<Content: View>: View {
    /// The identifier of the contact the message came from.
    let owner: String
    /// The depth the app is at. A sender hidden at it gets the plain message view: a card message can open at a
    /// duress depth (redemption runs at every depth), but nothing here may lead into the hidden contact.
    let depth: Int
    /// Where "Reply to {Name}" goes: the contact's details, with compose focused.
    let onReply: (ContactOpenRequest) -> Void
    @ViewBuilder let content: Content

    @Query private var contacts: [Contact.Profile]

    /// The sender's first name, set only when the sender is on Bob's side of a card whose bootstrap is still open.
    @State private var name: String?

    init(owner: String, depth: Int, onReply: @escaping (ContactOpenRequest) -> Void, @ViewBuilder content: () -> Content) {
        self.owner   = owner
        self.depth   = depth
        self.onReply = onReply
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

                    self.content
                }
                .safeAreaInset(edge: .bottom) {
                    VStack(alignment: .leading, spacing: 12) {
                        CardNotice(tone: .warn, IntroCardCopy.trustLine)

                        CardPrimaryButton(title: IntroCardCopy.replyButton(name: name)) {
                            self.onReply(ContactOpenRequest(identifier: self.owner, focusCompose: true))
                        }

                        Text(IntroCardCopy.replyNote(name: name))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
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
                contact.isVisible(atDepth: self.depth),
                case .conversation(_, _, _, _, _, let bootstrapOpen, let isIssuer) = contact.cardState,
                bootstrapOpen, isIssuer
            else { return }
            self.name = IntroCardCopy.firstName(of: contact.givenName.decrypt())
        }
    }
}
