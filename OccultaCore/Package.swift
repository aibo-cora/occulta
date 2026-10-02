// swift-tools-version: 6.2

import PackageDescription

// First-party, in-repo package. Apple frameworks only (Foundation, Security, CryptoKit):
// it must never declare a dependency — see §7 of `Docs/Audit/SECURITY_CHECKLIST.md`.
//
// No `defaultIsolation` setting, unlike the app's `MainActor`: what lives here is stateless,
// and pure functions have no reason to be pinned to the main thread.
let package = Package(
    name: "OccultaCore",
    platforms: [.iOS("18.6")],
    products: [
        .library(name: "OccultaCore", targets: ["OccultaCore"])
    ],
    targets: [
        .target(name: "OccultaCore")
    ]
)
