//
//  IntroCardMock+Gallery.swift
//  Occulta
//
//  Every introduction card mock in one list, in flow order. Open it from the
//  canvas, or launch a Debug build with `-IntroCardMocks`.
//

#if DEBUG
import SwiftUI

extension IntroCardMock {
    struct Gallery: View {
        @State private var showingMismatch = false

        var body: some View {
            NavigationStack {
                List {
                    Section("Bob issues a card") {
                        NavigationLink("1 · Pending contact") { IssuerPendingNoCard() }
                        NavigationLink("2 · Create card · W-01") { CreateCard() }
                        NavigationLink("3 · Share card · W-02") { Screen { ShareCardStep() } }
                        NavigationLink("4 · Active card · W-09") { IssuerPendingActiveCard() }
                        NavigationLink("Below iOS 26") { IssuerPendingNoCard(isCardSupported: false) }
                    }

                    Section("Carol uses it") {
                        NavigationLink("5 · Import, then write · W-05") { ImportCard() }
                        NavigationLink("5b · Import refused: already talking · W-16") { ImportCard(refusal: .alreadyTalking) }
                        NavigationLink("5c · Cards crossed, yours wins · W-17") { ImportCard(refusal: .ownCardOut) }
                        NavigationLink("6 · Before the first message · W-06") { RecipientBeforeFirstSend() }
                        NavigationLink("7 · Waiting for a reply · W-07") { RecipientWaitingForReply() }
                        NavigationLink("Import below iOS 26") { ImportCard(isCardSupported: false) }
                    }

                    Section("Bob receives it") {
                        NavigationLink("8 · First message · W-08") { IssuerFirstMessage() }
                        NavigationLink("9 · Card contact, discard · W-06, W-15") { IssuerCardContact() }
                    }

                    Section("Both") {
                        NavigationLink("10 · Contact list, both phones · W-06") { ContactsList() }
                        NavigationLink("11 · Blocked feature · W-10") { BlockedFeature() }
                        NavigationLink("12 · Exchange: match · W-12") { ExchangeMatch() }
                        Button("13 · Exchange: mismatch · W-11") { self.showingMismatch = true }
                    }
                }
                .navigationTitle("Introduction cards")
                .fullScreenCover(isPresented: self.$showingMismatch) {
                    NavigationStack { ExchangeMismatch() }
                }
            }
        }
    }
}

#Preview("Gallery") { IntroCardMock.Gallery() }
#Preview("1 · Pending") { NavigationStack { IntroCardMock.IssuerPendingNoCard() } }
#Preview("2 · Create") { NavigationStack { IntroCardMock.CreateCard() } }
#Preview("4 · Active card") { NavigationStack { IntroCardMock.IssuerPendingActiveCard() } }
#Preview("5 · Import") { NavigationStack { IntroCardMock.ImportCard() } }
#Preview("6 · Before first message") { NavigationStack { IntroCardMock.RecipientBeforeFirstSend() } }
#Preview("7 · Waiting") { NavigationStack { IntroCardMock.RecipientWaitingForReply() } }
#Preview("8 · First message") { NavigationStack { IntroCardMock.IssuerFirstMessage() } }
#Preview("9 · Card contact") { NavigationStack { IntroCardMock.IssuerCardContact() } }
#Preview("10 · List") { NavigationStack { IntroCardMock.ContactsList() } }
#Preview("11 · Blocked") { NavigationStack { IntroCardMock.BlockedFeature() } }
#Preview("12 · Match") { NavigationStack { IntroCardMock.ExchangeMatch() } }
#Preview("13 · Mismatch") { NavigationStack { IntroCardMock.ExchangeMismatch() } }
#endif
