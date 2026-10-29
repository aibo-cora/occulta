//
//  OnboardingTests.swift
//  OccultaTests
//
//  The onboarding's pages and copy. The drawing is view code and is checked on screen.
//
//  `WhatsNewTests`' hidden-state tripwire is deliberately not applied here, because the onboarding has
//  to name Secure Mode to introduce it. That is safe only because it shows before
//  `hasCompletedOnboarding` is set, which is before any PIN or depth can exist, and nothing in the app
//  resets the flag. If the onboarding ever becomes replayable from Settings, it would show on an
//  unlocked phone at any depth, and the What's New rule would apply to it too.
//

import Testing
@testable import Occulta

@Suite("Onboarding — pages and copy")
@MainActor
struct OnboardingTests {

    @Test("Secure Mode is introduced only with the feature on; the rest show in order", arguments: [true, false])
    func pagesInOrder(secureModeEnabled: Bool) {
        let expected: [OnboardingView.Page] = secureModeEnabled
            ? [.welcome, .meet, .sendAnywhere, .secureMode, .vault]
            : [.welcome, .meet, .sendAnywhere, .vault]

        #expect(OnboardingView.Page.pages(secureModeEnabled: secureModeEnabled) == expected)
    }

    /// `decisions.md`, "Restore discoverability": the onboarding points someone on a new phone to the
    /// Vault tab's restore item.
    @Test("The Vault page points to Restore from Backup")
    func vaultPagePointsToRestore() {
        #expect(OnboardingView.Page.vault.footnote.contains("+ menu in the Vault tab"))
    }

    /// The canvas's other modes gather at the screen's centre, under the page's drawing.
    @Test("Pages use only the spread-out particle modes, and the field changes with every page", arguments: [true, false])
    func particlePhases(secureModeEnabled: Bool) {
        let phases = OnboardingView.Page.pages(secureModeEnabled: secureModeEnabled).map(\.particlePhase)

        #expect(phases.allSatisfy { [0, 3, 5].contains($0) })
        #expect(zip(phases, phases.dropFirst()).allSatisfy { $0 != $1 })
    }

    /// Tripwire, not a guarantee. `Docs/Audit/LanguageRiskReview2026-08-01`: no framing against a named
    /// authority, and (its addendum) no overclaiming what the app protects. The previous onboarding
    /// shipped "subpoena" and "No legal process can retrieve what was never stored".
    @Test("No page names an authority or overclaims")
    func copyAvoidsRiskyLanguage() {
        let forbidden = [
            "subpoena", "law enforcement", "police", "government", "legal", "warrant", "border",
            "military", "unbreakable", "undetectable", "untraceable", "impossible", "guarantee"
        ]

        for page in OnboardingView.Page.allCases {
            let text = [page.label, page.title, page.message, page.footnote]
                .joined(separator: "\n")
                .lowercased()

            for word in forbidden {
                #expect(!text.contains(word), "\(page) mentions “\(word)”")
            }
        }
    }
}
