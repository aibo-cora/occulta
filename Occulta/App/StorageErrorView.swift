//
//  StorageErrorView.swift
//  Occulta
//
//  What a blocked launch shows (Bug 171, Stage 2c): the key reseal committed some of its work and then stopped, so the
//  store is a mix of old and new, and nothing may read or write it until the next launch finishes the job.
//
//  In place of the PIN prompt, so it comes before any PIN and is the same at every depth. It writes nothing, has no
//  retry button (a retry mid-session is what the epoch rule forbids), and its words name no keys, encryption, PIN or
//  Secure Mode: to whoever holds the phone it is a storage error, which is the likeliest cause (a full disk).
//
//  An `.occ` or `.occbak` handed to the app while this is up is dropped without being read or queued, and can be
//  opened again later; the copy iOS makes in the app's own Inbox is cleared when the app goes to the background, as
//  `RootView` clears it. Staged share-extension sessions stay where they are.
//

import SwiftUI

struct StorageErrorView: View {

    static let message = "Occulta couldn't finish updating its data. Make sure the iPhone has free storage, then reopen the app."

    @EnvironmentObject private var appScreen: AppScreen
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)

            Text(Self.message)
                .multilineTextAlignment(.center)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        // Removes the UIKit cover installed at launch, which nothing else will in this launch.
        .onAppear { self.appScreen.blockedViewAppeared() }
        // Dropped: not read, not queued.
        .onOpenURL { _ in }
        .onChange(of: self.scenePhase) { _, newPhase in
            if newPhase == .background { FileManager.default.clearInboxes() }
        }
    }
}
