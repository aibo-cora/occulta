//
//  ContactDetailV3.swift
//  Occulta
//

import SwiftUI
import SwiftData
import UIKit

// MARK: - Contact Detail V3

struct ContactDetailV3: View {
    let identifier: String

    @Query private var contacts: [Contact.Profile]

    @Environment(ContactManager.self)      private var contactManager
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(VaultManager.self)        private var vaultManager: VaultManager?
    @Environment(\.dismiss)               private var dismiss
    @Environment(\.scenePhase)            private var scenePhase

    @State private var editing          = false
    @State private var useThreadCompose = false
    @State private var composeVM: ComposeViewModel
    @State private var draftStore = DraftStore()

    init(identifier: String) {
        self.identifier = identifier
        self._contacts  = Query(filter: #Predicate { $0.identifier == identifier })
        self._composeVM = State(initialValue: ComposeViewModel(recipient: .contact(identifier)))
    }

    private var profile:    Contact.Profile? { self.contacts.first }
    private var givenName:  String { self.profile?.givenName.decrypt() ?? "" }
    private var familyName: String { self.profile?.familyName.decrypt() ?? "" }
    private var fullName:   String {
        [self.givenName, self.familyName].filter { !$0.isEmpty }.joined(separator: " ")
    }

    private var subtitle: String {
        [self.profile?.jobTitle.decrypt(), self.profile?.organizationName.decrypt()]
            .compactMap { s -> String? in (s?.isEmpty == false) ? s : nil }
            .joined(separator: " · ")
    }

    private var needsExchange: Bool {
        let keys = self.profile?.contactPublicKeys
        return (keys?.isEmpty ?? true) || keys?.last?.expiredOn != nil
    }

    @MainActor
    private var encryptionSchemeLabel: String { self.profile?.encryptionSchemeLabel ?? "" }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                IdentityStripV3(
                    avatarID:  self.identifier,
                    fullName:  self.fullName,
                    subtitle:  self.subtitle,
                    status:    self.profile?.verificationStatus ?? .pending,
                    thumbnail: self.profile?.imageData?.decrypt() ?? self.profile?.thumbnailImageData?.decrypt()
                )

                if !self.needsExchange {
                    ComposeToggleV3(useThread: Binding(
                        get: { self.useThreadCompose },
                        set: { newValue in
                            self.useThreadCompose = newValue
                            self.composeVM.clearAfterEncrypt()
                        }
                    ))

                    if self.useThreadCompose {
                        NavigationLink(destination: ComposableMessage(vm: self.composeVM)) {
                            HStack {
                                Text("Open thread")
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundStyle(.white)
                                if !self.composeVM.messages.isEmpty {
                                    Text("\(self.composeVM.messages.count)")
                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                        .foregroundStyle(.white)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 2)
                                        .background(Capsule().fill(.white.opacity(0.3)))
                                }
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Color.occultaAccent)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        }
                    } else {
                        let cm  = self.contactManager
                        let scm = self.shardCustodyManager
                        let vlt = self.vaultManager
                        ComposeHeroV3(
                            vm:              self.composeVM,
                            headerRight:     "→ TO \(self.givenName.uppercased())",
                            encryptLabel:    "Encrypt",
                            isForwardSecret: self.profile?.hasPrekeyAvailable,
                            onEncrypt:       { await self.composeVM.encrypt(contactManager: cm, shardCustodyManager: scm, vaultManager: vlt) }
                        )
                    }

                    Text(self.encryptionSchemeLabel)
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 16)
            .padding(.bottom, 16)
        }
        .background(Color(.systemGroupedBackground))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { self.editing = true } label: {
                    Label("Edit", systemImage: "pencil")
                }
            }
        }
        .task {
            self.composeVM.setup(contactManager: self.contactManager)
            if let loaded = self.draftStore.load(
                recipientID:       self.composeVM.recipientIDString,
                modelContext:      self.contactManager.modelContext
            ) {
                self.composeVM.draftText = loaded.text
                self.composeVM.messages  = loaded.messages
                self.useThreadCompose    = loaded.wasThreadMode
            }
        }
        .onChange(of: self.composeVM.draftText) { _, _ in self.scheduleDraftSave() }
        .onChange(of: self.composeVM.messages)  { _, _ in self.scheduleDraftSave() }
        .onDisappear {
            Task {
                await self.draftStore.flush(
                    recipientID:       self.composeVM.recipientIDString,
                    isSensitive:       self.composeVM.isSensitive(contactManager: self.contactManager),
                    text:              self.composeVM.draftText,
                    messages:          self.composeVM.messages,
                    useThread:         self.useThreadCompose,
                    modelContext:      self.contactManager.modelContext
                )
                self.composeVM.cleanup()
            }
        }
        .onChange(of: self.scenePhase) { _, newPhase in self.flushOnBackground(newPhase) }
        .fullScreenCover(isPresented: self.$editing) {
            Contact.FormV2(mode: .edit(identifier: self.identifier)) { self.dismiss() }
        }
        .sheet(item: self.$composeVM.encryptedURL) { url in
            ActivityView(activityItems: [url], onComplete: { completed in
                try? FileManager.default.removeItem(at: url)
                if completed { self.composeVM.clearAfterEncrypt() }
            })
        }
        .alert("Error", isPresented: self.$composeVM.isShowingError) {
            Button("OK") { }
        } message: {
            Text(self.composeVM.errorMessage)
        }
    }

    private func scheduleDraftSave() {
        let composeVM      = self.composeVM
        let contactManager = self.contactManager
        self.draftStore.scheduleSave(
            recipientID:       composeVM.recipientIDString,
            isSensitive:       { composeVM.isSensitive(contactManager: contactManager) },
            text:              composeVM.draftText,
            messages:          composeVM.messages,
            useThread:         self.useThreadCompose,
            modelContext:      contactManager.modelContext
        )
    }

    /// `.onDisappear` only fires on navigation away — it doesn't fire when the
    /// app backgrounds while this screen stays on top (a phone call, switching
    /// apps). The debounced auto-save alone doesn't cover that: an edit made
    /// in the last couple seconds before backgrounding may not have fired yet,
    /// and iOS can suspend the process before a plain Task gets to run. A
    /// background task assertion buys the time to flush immediately instead.
    ///
    /// `taskID` lives in a small reference box, not a local `var` — if
    /// `scenePhase` bounces away from `.active` more than once in quick
    /// succession, each call gets its own box, so each ends exactly the
    /// assertion it started, rather than a shared slot letting one call's
    /// cleanup end another's.
    private func flushOnBackground(_ newPhase: ScenePhase) {
        guard newPhase != .active else { return }
        let taskBox = BackgroundTaskBox()
        taskBox.id = UIApplication.shared.beginBackgroundTask {
            UIApplication.shared.endBackgroundTask(taskBox.id)
        }
        Task {
            await self.draftStore.flush(
                recipientID:       self.composeVM.recipientIDString,
                isSensitive:       self.composeVM.isSensitive(contactManager: self.contactManager),
                text:              self.composeVM.draftText,
                messages:          self.composeVM.messages,
                useThread:         self.useThreadCompose,
                modelContext:      self.contactManager.modelContext
            )
            UIApplication.shared.endBackgroundTask(taskBox.id)
        }
    }
}

/// Holds a `UIBackgroundTaskIdentifier` across the expiration handler and the
/// completion of the `Task` that uses it. A plain local `var` reassigned after
/// `beginBackgroundTask`'s expiration closure has already captured it trips
/// Swift's "mutated after capture by Sendable closure" diagnostic; mutating a
/// property on a captured reference type instead doesn't hit that check.
/// Shared with `GroupDetailV3` and `ContactDetailV2`, which have the identical
/// `flushOnBackground` — not `private` since it needs to be visible there too.
final class BackgroundTaskBox: @unchecked Sendable {
    var id: UIBackgroundTaskIdentifier = .invalid
}

// MARK: - Identity Strip (shared)

struct IdentityStripV3: View {
    let avatarID:  String
    let fullName:  String
    let subtitle:  String
    let status:    VerificationStatus?
    let thumbnail: Data?

    var body: some View {
        HStack(spacing: 14) {
            SwiftUI.Group {
                if let data = self.thumbnail, let img = UIImage(data: data) {
                    Image(uiImage: img).resizable().scaledToFill()
                } else {
                    ZStack {
                        avatarGradientV2(for: self.avatarID)
                        Text(self.fullName.initials)
                            .font(.system(size: 18, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                }
            }
            .frame(width: 52, height: 52)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 3) {
                Text(self.fullName)
                    .font(.system(size: 19, weight: .bold))
                    .tracking(-0.4)
                    .lineLimit(1)
                if !self.subtitle.isEmpty {
                    Text(self.subtitle)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            if let status = self.status {
                StatusChipV3(status: status)
            }
        }
    }
}

// MARK: - Status Chip (shared)

struct StatusChipV3: View {
    let status: VerificationStatus

    var body: some View {
        Text(self.status.chipLabel)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .tracking(1.2)
            .foregroundStyle(self.status == .pending ? AnyShapeStyle(.secondary) : AnyShapeStyle(.white))
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(
                SwiftUI.Group {
                    if self.status == .pending {
                        RoundedRectangle(cornerRadius: 4)
                            .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [3, 2]))
                            .foregroundStyle(.secondary)
                    } else {
                        RoundedRectangle(cornerRadius: 4).fill(self.status.color)
                    }
                }
            )
    }
}

// MARK: - Compose Toggle (shared)

struct ComposeToggleV3: View {
    @Binding var useThread: Bool

    var body: some View {
        HStack {
            Text("compose style")
                .font(.system(size: 11, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { self.useThread.toggle() }
            } label: {
                HStack(spacing: 6) {
                    if self.useThread {
                        Circle()
                            .fill(Color.occultaAccent)
                            .frame(width: 8, height: 8)
                        Text("Thread")
                            .font(.system(size: 11, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Color.occultaAccent)
                    } else {
                        Circle()
                            .strokeBorder(Color(.separator), lineWidth: 1.5)
                            .frame(width: 8, height: 8)
                        Text("Quick")
                            .font(.system(size: 11, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(Color(.tertiarySystemFill))
                .clipShape(Capsule())
            }
            .buttonStyle(.plain)
        }
    }
}
