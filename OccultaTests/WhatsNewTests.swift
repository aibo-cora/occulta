//
//  WhatsNewTests.swift
//  OccultaTests
//
//  `WhatsNew.release(for:lastSeen:in:)` is the whole of the "show once, on update" decision, and
//  it runs after whichever PIN unlocks the app. These cover its table, and the real catalog's
//  shape and wording. The fresh-install stamp lives in `RootView` and is checked by hand: a fresh
//  install never shows the page, and an update from a build without the feature does, once.
//

import Testing
import Foundation
@testable import Occulta

@Suite("What's New — shown once per updated version")
@MainActor
struct WhatsNewTests {

    private let notes = WhatsNew.Release(
        version: "2.0.0",
        features: [WhatsNew.Feature(symbol: "sparkles", title: "Title", detail: "Detail")],
        fixes: ["Fixed a thing."]
    )

    @Test("An update to a version with notes shows them")
    func updateShowsNotes() {
        let shown = WhatsNew.release(for: "2.0.0", lastSeen: "1.11.1", in: [self.notes])

        #expect(shown == self.notes)
    }

    @Test("An install that never acknowledged a version shows the current one")
    func neverAcknowledgedShowsNotes() {
        // Someone updating from a build that predates the feature: onboarding done, nothing stamped.
        let shown = WhatsNew.release(for: "2.0.0", lastSeen: "", in: [self.notes])

        #expect(shown == self.notes)
    }

    @Test("The acknowledged version is not shown again")
    func acknowledgedVersionIsNotShownAgain() {
        let shown = WhatsNew.release(for: "2.0.0", lastSeen: "2.0.0", in: [self.notes])

        #expect(shown == nil)
    }

    @Test("A version with no entry shows nothing")
    func versionWithoutEntryShowsNothing() {
        let shown = WhatsNew.release(for: "2.0.1", lastSeen: "2.0.0", in: [self.notes])

        #expect(shown == nil)
    }

    @Test("Only the current version's entry is chosen")
    func choosesTheCurrentVersionsEntry() {
        let older = WhatsNew.Release(version: "1.11.0", features: [], fixes: ["Older fix."])

        let shown = WhatsNew.release(for: "2.0.0", lastSeen: "1.10.0", in: [older, self.notes])

        #expect(shown == self.notes)
    }

    @Test("An empty catalog shows nothing")
    func emptyCatalogShowsNothing() {
        #expect(WhatsNew.release(for: "2.0.0", lastSeen: "1.11.1", in: []) == nil)
    }

    @Test("Settings' lookup returns the entry whether or not it was acknowledged")
    func notesIgnoreTheAcknowledgedStamp() {
        // `release(for:lastSeen:)` returns nil for this version once it is acknowledged;
        // the Settings row has to keep working after that.
        #expect(WhatsNew.release(for: "2.0.0", lastSeen: "2.0.0", in: [self.notes]) == nil)
        #expect(WhatsNew.notes(for: "2.0.0", in: [self.notes]) == self.notes)
    }

    @Test("Settings' lookup returns nothing for a version with no entry")
    func notesForVersionWithoutEntry() {
        #expect(WhatsNew.notes(for: "2.0.1", in: [self.notes]) == nil)
    }

    // MARK: - The shipped catalog

    @Test("Every shipped entry is well formed")
    func shippedCatalogIsWellFormed() {
        let versions = WhatsNew.releases.map(\.version)

        #expect(Set(versions).count == versions.count, "two entries for one version")

        for release in WhatsNew.releases {
            #expect(!release.version.isEmpty)
            #expect(
                !release.features.isEmpty || !release.fixes.isEmpty,
                "\(release.version) has nothing to show"
            )
            #expect(
                release.version.split(separator: ".").count == 3
                    && release.version.split(separator: ".").allSatisfy { Int($0) != nil },
                "\(release.version) is not a marketing version like 2.0.0"
            )
        }
    }

    /// Tripwire, not a guarantee: it catches the obvious names and nothing subtler. The copy is
    /// compiled into the binary and shown on an unlocked phone, so it must not name hidden state.
    @Test("No shipped entry names a hidden-state mechanism")
    func shippedCatalogNamesNoMechanism() {
        let forbidden = [
            "secure mode", "duress", "depth", "decoy", "hidden", "coerc",
            "trustee", "shard", "panic", "plausible", "deniab"
        ]

        for release in WhatsNew.releases {
            let text = (release.features.flatMap { [$0.title, $0.detail] } + release.fixes)
                .joined(separator: "\n")
                .lowercased()

            for word in forbidden {
                #expect(!text.contains(word), "\(release.version) mentions “\(word)”")
            }
        }
    }
}
