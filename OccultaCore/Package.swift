// swift-tools-version: 6.2

import PackageDescription

// First-party, in-repo package. Apple frameworks only (Foundation, Security, CryptoKit):
// it must never declare a dependency — see §7 of `Docs/Audit/SECURITY_CHECKLIST.md`.
//
// No `defaultIsolation` setting, unlike the app's `MainActor`: what lives here is stateless,
// and pure functions have no reason to be pinned to the main thread.
//
// Two products. `OccultaCore` is the API other apps can use. `OccultaFormats` is Occulta's own
// wire and at-rest formats, linked by the app only: they carry Occulta-identifying constants that
// are wire format (the `OCCB` magic, the `occulta-signed-attribute-v2` prefix), so a host app
// using them would put Occulta's name in every message it sends.
//
// `OccultaFormats` depends on `OccultaCore`, never the reverse: formats are built on the primitives,
// and the public API must not reach Occulta's formats.
let package = Package(
    name: "OccultaCore",
    platforms: [.iOS("18.6")],
    products: [
        .library(name: "OccultaCore", targets: ["OccultaCore"]),
        .library(name: "OccultaFormats", targets: ["OccultaFormats"])
    ],
    targets: [
        .target(name: "OccultaCore"),
        .target(name: "OccultaFormats", dependencies: ["OccultaCore"]),
        // Uses OccultaCore as another app would: no `@testable`, no OccultaFormats. The app's
        // own tests can't show this, since the app links both modules.
        .testTarget(name: "OccultaCoreAPITests", dependencies: ["OccultaCore"])
    ]
)
