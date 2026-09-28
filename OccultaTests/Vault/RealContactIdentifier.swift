//
//  RealContactIdentifier.swift
//  OccultaTests
//
//  A stored `Contact.Profile.identifier` is the base64 of encrypted bytes (SecurityReview
//  2026-07-24 finding #11), not a UUID. Backup-key tests used UUID strings and short labels,
//  which is how an assumption that identifiers are UUIDs broke every real distribution and
//  restore without a test failing (`bugs.md` Bugs 145–147). Use this instead.
//

import Foundation
@testable import Occulta

/// A contact identifier in the form the app stores: base64 of 64 random bytes, 88 characters.
func realFormatContactIdentifier() -> String {
    Data.randomBytes(64).base64EncodedString()
}
