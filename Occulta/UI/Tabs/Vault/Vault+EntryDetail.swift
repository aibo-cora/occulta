//
//  Vault+EntryDetail.swift
//  Occulta
//
//  Entry detail pushed from the Vault list.
//  Content is blurred at rest; a press-and-hold gesture reveals it.
//

import SwiftUI
import SwiftData

struct VaultEntryDetail: View {
    let entryID: UUID

    @Environment(VaultManager.self) private var vault
    @Environment(ShardCustodyManager.self) private var shardCustodyManager: ShardCustodyManager?
    @Environment(\.dismiss) private var dismiss

    @Query private var entries: [VaultEntry]

    @State private var cachedLabel     = ""
    @State private var cachedType      = VaultEntryType.note
    @State private var showDeleteAlert = false
    @GestureState private var isHeld   = false

    init(entryID: UUID) {
        self.entryID  = entryID
        self._entries = Query(filter: #Predicate<VaultEntry> { $0.id == entryID })
    }

    private var entry: VaultEntry? { self.entries.first }

    var body: some View {
        ScrollView {
            if let entry {
                VStack(alignment: .leading, spacing: 16) {
                    self.hero(entry: entry)
                    self.contentCard(entry: entry)
                    self.metaCard(entry: entry)
                    self.provenance
                }
                .padding(16)
            } else {
                ContentUnavailableView("Entry not found", systemImage: "lock.slash")
            }
        }
        .privacySensitive(true)
        .background(Color(.systemGroupedBackground))
        .safeAreaInset(edge: .bottom) {
            if let entry {
                VStack(spacing: 0) {
                    Divider()
                    actionStrip(entry: entry)
                        .padding(.horizontal, 16)
                        .padding(.top, 10)
                        .padding(.bottom, 12)
                }
                .background(Color(.systemGroupedBackground))
            }
        }
        .navigationBarTitleDisplayMode(.inline)
        .alert("Delete Entry?", isPresented: self.$showDeleteAlert) {
            Button("Delete", role: .destructive) {
                guard let entry else { return }
                self.vault.extendSession()
                
                try? self.vault.deleteEntry(id: entry.id)
                
                self.dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently removes the encrypted entry.")
        }
        .onAppear {
            self.vault.extendSession()
            if let entry, let payload = try? self.vault.decryptLabelPayload(for: entry) {
                self.cachedLabel = payload.label
                self.cachedType  = payload.type
            }
        }
        .onChange(of: self.vault.isUnlocked) { _, isUnlocked in
            guard !isUnlocked else { return }
            // Vault locked while detail is visible — clear the cached plaintext label
            // and navigate back so Face ID is required to re-enter.
            self.cachedLabel = ""
            self.dismiss()
        }
    }

    // MARK: - Hero

    private func hero(entry: VaultEntry) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 14)
                    .fill(self.cachedType.tileBackground)
                    .frame(width: 52, height: 52)
                Text(self.cachedType.emoji)
                    .font(.system(size: 26))
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(self.cachedLabel)
                    .font(.system(size: 20, weight: .bold))
                    .tracking(-0.3)
                Text(self.cachedType.displayName)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .tracking(0.5)
                    .textCase(.uppercase)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: - Content (hold-to-reveal)
    
    private var text: String? {
        guard
            let entry = self.entry,
            let data = try? self.vault.decryptContent(for: entry)
        else { return nil }
        
        return String(data: data, encoding: .utf8)
    }

    private func contentCard(entry: VaultEntry) -> some View {
        ZStack(alignment: .center) {
            SwiftUI.Group {
                if let text = self.text {
                    Text(text)
                        .font(.system(size: 13, design: .monospaced))
                        .lineSpacing(4)
                        .textSelection(.disabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                } else {
                    Text("binary · \(entry.encryptedContent.count) bytes")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .padding(14)
                }
            }
            .blur(radius: self.isHeld ? 0 : 8)
            .animation(.easeInOut(duration: 0.15), value: self.isHeld)

            if !self.isHeld {
                HStack(spacing: 6) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 11))
                    Text("HOLD TO REVEAL")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .tracking(0.8)
                }
                .foregroundStyle(.secondary)
                .padding(.horizontal, 12)
                .padding(.vertical, 5)
                .background(Capsule().fill(Color(.tertiarySystemGroupedBackground)))
                .overlay(Capsule().strokeBorder(Color.primary.opacity(0.1), lineWidth: 0.5))
            }
        }
        .frame(minHeight: 80)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .gesture(
            DragGesture(minimumDistance: 0)
                .updating(self.$isHeld) { _, state, _ in state = true }
        )
        // Once when the hold starts, not continuously while held (Bug 136).
        .onChange(of: self.isHeld) { _, held in
            if held { self.vault.extendSession() }
        }
    }

    // MARK: - Metadata card

    private func metaCard(entry: VaultEntry) -> some View {
        VStack(spacing: 0) {
            self.metaRow(title: "Encrypted With") {
                Text("SE key · this device only")
                    .font(.system(size: 13, design: .monospaced))
            }

            Divider().padding(.leading, 16)

            self.metaRow(title: "Created") {
                Text(entry.createdAt.formatted(date: .long, time: .omitted))
                    .font(.system(size: 15))
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    private func metaRow<Content: View>(
        title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        HStack(alignment: .center) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title.uppercased())
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .tracking(1.2)
                content()
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - Provenance note (green info block per spec)

    private var provenance: some View {
        HStack(alignment: .top, spacing: 8) {
            Text("🛡")
                .font(.system(size: 13))
            Text("Encrypted with a P-256 key bound to the Secure Enclave of this device. Decryption requires biometric authentication matching the enrolled set at key creation time. Key material never leaves the SE.")
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(VaultEntryType.cat(light: (0x6e, 0xc9, 0x7e), dark: (0x3B, 0x6D, 0x11)))
                .lineSpacing(3)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VaultEntryType.cat(light: (0xEA,0xF3,0xDE), dark: (0x1a,0x2e,0x1a)))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }

    // MARK: - Action strip (text-only buttons per spec)

    private enum ActionButtonStyle { case standard, primary, danger }

    private func actionButton(_ label: String, style: ActionButtonStyle) -> some View {
        Text(label.uppercased())
            .font(.system(size: 11, weight: .semibold, design: .monospaced))
            .tracking(0.8)
            .frame(maxWidth: .infinity)
            .frame(height: 44)
            .foregroundStyle(style == .danger ? Color.occultaDanger : Color.primary)
            .background(style == .primary
                ? Color(.tertiarySystemGroupedBackground)
                : Color(.secondarySystemGroupedBackground))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .strokeBorder(
                        style == .danger
                            ? Color.occultaDanger.opacity(0.3)
                            : Color.primary.opacity(0.1),
                        lineWidth: 0.5
                    )
            )
    }

    private func actionStrip(entry: VaultEntry) -> some View {
        HStack(spacing: 8) {
            Button {
                self.vault.extendSession()
                if let data = try? vault.decryptContent(for: entry),
                   let str  = String(data: data, encoding: .utf8) {
                    UIPasteboard.general.copySensitive(str)
                }
            } label: {
                self.actionButton("Copy", style: .standard)
            }
            .buttonStyle(.plain)

            Button { self.showDeleteAlert = true } label: {
                self.actionButton("Delete", style: .danger)
            }
            .buttonStyle(.plain)
        }
    }
}
