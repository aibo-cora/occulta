//
//  WhatsNew.swift
//  Occulta
//

import Foundation

/// What changed in each release, shown once, full screen, the first time the app is opened after
/// an update.
///
/// **When it shows.** The marketing version (`CFBundleShortVersionString`) differs from the one
/// last acknowledged, and `releases` has an entry for it. A build-number bump, or a release with
/// no entry, shows nothing. The version is acknowledged when the user taps Continue, so quitting
/// the app before reading it shows it again next launch.
///
/// **Who it never shows to.** A fresh install. `RootView` stamps the current version while
/// onboarding is on screen, so a new user's first launch is not "what's new" in an app they have
/// just installed.
///
/// **Why the decision takes nothing but persisted state.** It runs after whichever PIN unlocks
/// the app, at every depth, so what it reads has to be the same at every depth. Both inputs are
/// global: the bundle's version and one `UserDefaults` string. The first unlock after an update
/// shows it and consumes it, whichever depth that was, and nothing about the screen or the
/// decision differs between depths.
///
/// **Writing an entry.** The text is compiled into the binary and shown to whoever is looking at
/// an unlocked phone, so it follows the same rule as the alert copy in `RootView`: describe what
/// changed for the user, never the mechanism. A fix in a sensitive area reads as a general
/// reliability fix. Do not name Secure Mode, depths, trustees, shards or anything else that would
/// tell a reader hidden state exists. `WhatsNewTests` fails on a word list of these, which catches
/// the obvious ones and nothing subtler, so review the copy too.
enum WhatsNew {

    /// `UserDefaults` key holding the last acknowledged marketing version. Empty until a fresh
    /// install stamps it or an update's Continue does. The name discloses nothing, and the value
    /// is the same string the bundle's `Info.plist` already carries.
    static let lastSeenKey = "whatsNewLastSeenVersion"

    struct Feature: Equatable {
        /// SF Symbol name.
        let symbol: String
        let title: String
        let detail: String
    }

    struct Release: Equatable {
        /// Marketing version this entry is for, e.g. `"2.0.0"`.
        let version: String
        let features: [Feature]
        /// One line each.
        let fixes: [String]
    }

    /// One entry per release that has something to say, in any order. Add the entry for a
    /// version when cutting it; a version without one simply shows nothing.
    ///
    ///     Release(
    ///         version: "2.0.0",
    ///         features: [Feature(symbol: "lock.shield", title: "…", detail: "…")],
    ///         fixes: ["…"]
    ///     )
    static let releases: [Release] = {
        let entries: [Release] = []

        // Debug builds only, so the page and the Settings row can be seen without a real entry.
        // Compiled out of Release, where an empty catalog shows nothing.
        #if DEBUG
        return entries + [
            Release(
                version: Bundle.main.appVersion,
                features: [
                    Feature(symbol: "sparkles", title: "Sample feature (debug builds only)", detail: "What it does for you, in a sentence or two."),
                    Feature(symbol: "bolt.fill", title: "Another sample feature", detail: "A second line of detail, long enough to wrap onto a second line on a phone screen.")
                ],
                fixes: ["Sample fix: a problem that could cause something to go wrong."]
            )
        ]
        #else
        return entries
        #endif
    }()

    /// `version`'s entry, whether or not it has been acknowledged. What Settings reads.
    static func notes(for version: String, in catalog: [Release] = WhatsNew.releases) -> Release? {
        catalog.first { $0.version == version }
    }

    /// The entry to show for `version`, or `nil` when `lastSeen` already is `version` or
    /// `catalog` has nothing for it.
    static func release(for version: String, lastSeen: String, in catalog: [Release] = WhatsNew.releases) -> Release? {
        guard lastSeen != version else { return nil }

        return self.notes(for: version, in: catalog)
    }
}
