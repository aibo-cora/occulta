//
//  CardMeetingVerdictView.swift
//  Occulta
//
//  What the in-person check found about an earlier card conversation (`Docs/Features/Introduction Cards/SPEC.md`
//  §7, Q-10): W-12 when the earlier messages went to this person, W-11 when they didn't. Shown only after the
//  ceremony's own confirmation succeeded; by then the contact is verified, so this is the one screen where green
//  is allowed for a contact who started on a card. Nothing about the verdict is stored.
//

import SwiftUI

struct CardMeetingVerdictView: View {
    let verdict: CardMeetingVerdict
    /// The contact, for the avatar and the name in the copy.
    let identifier: String
    let fullName:   String
    /// Called when the user is done: after "I understand" for a mismatch, after "Done" for a match.
    let onDone: () -> Void

    private var name: String { IntroCardCopy.firstName(of: self.fullName) }

    var body: some View {
        switch self.verdict {
        case .none:
            EmptyView()
        case .match:
            self.screen {
                CardNotice(tone: .verified, IntroCardCopy.exchangeMatch(name: self.name))
                CardPrimaryButton(title: "Done", action: self.onDone)
            }
        case .mismatch:
            // W-11 needs an acknowledgment: no swipe, no back button, no tap outside. It is a message about
            // something that happened, so it is gone once acknowledged and nothing keeps it.
            self.screen {
                CardNotice(tone: .danger, IntroCardCopy.exchangeMismatch(name: self.name))
                CardPrimaryButton(title: IntroCardCopy.acknowledgeButton, action: self.onDone)
            }
            .interactiveDismissDisabled()
        }
    }

    private func screen<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        CardScreen {
            HStack(spacing: 14) {
                ZStack {
                    avatarGradientV2(for: self.identifier)
                    Text(self.fullName.initials)
                        .font(.system(size: 18, weight: .semibold, design: .rounded))
                        .foregroundStyle(.white)
                }
                .frame(width: 52, height: 52)
                .clipShape(Circle())

                Text(self.fullName)
                    .font(.system(size: 19, weight: .bold))
                    .tracking(-0.4)
                    .lineLimit(1)

                Spacer()

                StatusChipV3(status: .verified)
            }

            content()
        }
        .navigationBarBackButtonHidden()
    }
}

#Preview("Match") {
    CardMeetingVerdictView(verdict: .match, identifier: "preview-carol", fullName: "Carol Reyes", onDone: {})
}

#Preview("Mismatch") {
    CardMeetingVerdictView(verdict: .mismatch, identifier: "preview-carol", fullName: "Carol Reyes", onDone: {})
}
