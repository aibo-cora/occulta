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
        let entries: [Release] = [
            Release(
                version: "2.0.0",
                features: [
                    Feature(
                        symbol: "person.crop.rectangle.badge.plus",
                        title: "Introduction Cards",
                        detail: "Can't meet someone yet? Send them an introduction card over any channel so they can write to you first. They're marked Not verified until you meet in person, and the exchange then checks that they're who you were writing to. Needs iOS 26 on both phones."
                    ),
                    Feature(
                        symbol: "lock.shield",
                        title: "See how your message will be protected",
                        detail: "Before you send, Occulta tells you whether the message will be Single View with forward secrecy, use a temporary key, or use a long-term key, and what each one means."
                    ),
                    Feature(
                        symbol: "arrow.triangle.2.circlepath",
                        title: "Forward secrecy lasts longer",
                        detail: "Occulta now refills your contacts' one-time keys before they run out, so conversations stay protected through long exchanges."
                    ),
                    Feature(
                        symbol: "cpu",
                        title: "Stronger protection on your phone",
                        detail: "Data stored on this device is now sealed under keys more tightly bound to the Secure Enclave. Phones that update to iOS 26 are upgraded to post-quantum protection automatically. This happens at launch, with nothing to do."
                    ),
                    Feature(
                        symbol: "video.fill",
                        title: "Share videos from Photos",
                        detail: "Occulta now appears in the share sheet for videos, up to 100 MB."
                    )
                ],
                fixes: [
                    "Opening an old or unrelated response file no longer shows a false \"Verification failed\" warning.",
                    "Group messages are now checked more strictly when opened.",
                    "Group messages can now carry attachments, including videos, which were refused before.",
                    "Occulta's folder no longer appears in the Files app.",
                    "Files you received but never opened are now cleaned up instead of lingering.",
                    "Erase All Data now also clears temporary sharing data.",
                    "The key exchange now stops searching when you leave its screen."
                ]
            )
        ]

        // Debug builds only, so the page and the Settings row can be seen without a real entry.
        // Skipped once the running version has one, which would otherwise be two entries for it.
        // Compiled out of Release, where a version without an entry shows nothing.
        #if DEBUG
        guard !entries.contains(where: { $0.version == Bundle.main.appVersion }) else { return entries }

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
