//
//  Manager+Paths.swift
//  Occulta
//

import Foundation

extension Manager {
    /// Where the app keeps files outside SwiftData.
    ///
    /// Release builds, and a Debug build that isn't a test host, return the system's Application Support directory,
    /// exactly what each call site resolved before. A test host (Debug, `XCTestCase` loaded) returns a directory of its
    /// own, so a test that writes or deletes a file there can't reach the files of an install on the device it runs on
    /// (Bug 191: `backup-export-meta.dat`, the drafts' attachment folders, the reseal's temporary files). Nothing else
    /// resolves `applicationSupportDirectory`: `ApplicationSupportRoutingTests` fails if something does.
    nonisolated enum Paths {

        static var applicationSupport: URL {
            #if DEBUG
            if NSClassFromString("XCTestCase") != nil {
                // Created on every call: the host clears the temporary directory at launch.
                try? FileManager.default.createDirectory(at: Self.testHost, withIntermediateDirectories: true)
                return Self.testHost
            }
            #endif
            return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        }

        #if DEBUG
        private static let testHost = FileManager.default.temporaryDirectory
            .appendingPathComponent("occulta-test-host-\(UUID().uuidString)", isDirectory: true)
        #endif
    }
}
