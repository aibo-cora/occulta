//
//  TrustScenarioCopyTests.swift
//  OccultaTests
//
//  Everything Trust Check says is shown at every depth, so none of it may name hidden state. The word list is
//  `HiddenStateWordList`, the same one `WhatsNewTests` uses. A tripwire, not a guarantee: a person reviews the
//  copy for anything subtler, in every language the app ships.
//

import Testing
@testable import Occulta

@MainActor
@Suite("Trust Check — copy names no hidden-state mechanism")
struct TrustScenarioCopyTests {

    /// Every string the flow can show for a scenario, for a contact and for none.
    private func texts(for scenario: TrustScenario) -> [String] {
        var texts = [scenario.title(), scenario.title(name: "Alex"), scenario.subtitle, scenario.pickerTitle, scenario.emptyListText]

        for status in [VerificationStatus.verified, .unverified, .pending] {
            for canRevoke in [true, false] {
                let remedy = TrustRemedy.make(for: scenario, status: status, canRevoke: canRevoke)
                let content = remedy.content(for: scenario, status: status, name: scenario.needsContact ? "Alex" : nil)

                texts += [content.heading] + content.steps + [content.footnote].compactMap { $0 }
                texts.append(remedy.line(for: scenario, status: status))
            }
        }

        return texts
    }

    @Test("Every scenario title, picker line and remedy text passes the word list", arguments: TrustScenario.allCases)
    func scenarioCopy(_ scenario: TrustScenario) {
        for text in self.texts(for: scenario) {
            #expect(HiddenStateWordList.violations(in: text).isEmpty, "\(scenario): “\(text)”")
        }
    }

    @Test("The revoke confirmation and the file copy pass the word list")
    func sharedCopy() {
        let texts = [
            RevokeConfirmationCopy.title(name: "Alex"), RevokeConfirmationCopy.message, RevokeConfirmationCopy.button(name: "Alex"),
            FileNotOpenedCopy.alert, FileNotOpenedCopy.remedy,
        ]

        for text in texts {
            #expect(HiddenStateWordList.violations(in: text).isEmpty, "“\(text)”")
        }
    }

    @Test("A contact's name fills every placeholder: no text is left with a stray brace")
    func noUnfilledPlaceholders() {
        for scenario in TrustScenario.allCases {
            for text in self.texts(for: scenario) {
                #expect(!text.contains("{") && !text.contains("}"), "\(scenario): “\(text)”")
            }
        }
    }

    @Test("The word list catches what it is for")
    func wordListCatches() {
        #expect(!HiddenStateWordList.violations(in: "Hidden in Secure Mode, at a duress depth").isEmpty)
        #expect(HiddenStateWordList.violations(in: "Revoke Alex's key").isEmpty)
    }
}
