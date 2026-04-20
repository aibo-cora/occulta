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
    @Environment(\.dismiss) private var dismiss

    @Query private var entries: [VaultEntry]

    @State private var cachedLabel     = ""
    @State private var showDeleteAlert = false
    @GestureState private var isHeld   = false

    init(entryID: UUID) {
        self.entryID  = entryID
        self._entries = Query(filter: #Predicate<VaultEntry> { $0.id == entryID })
    }

    private var entry: VaultEntry? { entries.first }

    var body: some View {
        ScrollView {
            if let entry {
                VStack(alignment: .leading, spacing: 16) {
                    hero(entry: entry)
                    contentCard(entry: entry)
                    metaCard(entry: entry)
                    provenance
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
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button { showDeleteAlert = true } label: {
                    Image(systemName: "trash")
                        .foregroundStyle(Color.occultaDanger)
                }
            }
        }
        .alert("Delete Entry?", isPresented: $showDeleteAlert) {
            Button("Delete", role: .destructive) {
                guard let entry else { return }
                try? vault.deleteEntry(id: entry.id)
                dismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently removes the encrypted entry. Distributed shards remain valid.")
        }
        .onAppear {
            if let entry {
                cachedLabel = (try? vault.decryptLabel(for: entry)) ?? entry.type.displayName
            }
        }
    }

    // MARK: - Hero

    private func hero(entry: VaultEntry) -> some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 14)
                    .fill(entry.type.tileBackground)
                    .frame(width: 52, height: 52)
                Text(entry.type.emoji)
                    .font(.system(size: 26))
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(cachedLabel)
                    .font(.system(size: 20, weight: .bold))
                    .tracking(-0.3)
                Text(entry.type.displayName)
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

    private func contentCard(entry: VaultEntry) -> some View {
        let text: String? = {
            guard let data = try? vault.decryptContent(for: entry) else { return nil }
            return String(data: data, encoding: .utf8)
        }()

        return ZStack(alignment: .center) {
            Group {
                if let text {
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
            .blur(radius: isHeld ? 0 : 8)
            .animation(.easeInOut(duration: 0.15), value: isHeld)

            if !isHeld {
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
                .updating($isHeld) { _, state, _ in state = true }
        )
    }

    // MARK: - Metadata card

    private func metaCard(entry: VaultEntry) -> some View {
        VStack(spacing: 0) {
            metaRow(title: "Encrypted With") {
                Text("SE key · this device only")
                    .font(.system(size: 13, design: .monospaced))
            }

            Divider().padding(.leading, 16)

            metaRow(title: "Created") {
                Text(entry.createdAt.formatted(date: .long, time: .omitted))
                    .font(.system(size: 15))
            }

            if entry.shardDistributionEncrypted != nil {
                Divider().padding(.leading, 16)

                NavigationLink {
                    VaultShardSetup(entryID: entry.id)
                } label: {
                    metaRow(title: "Shamir Shards") {
                        Text("Active — tap to manage")
                            .font(.system(size: 15))
                            .foregroundStyle(.primary)
                    }
                }
                .buttonStyle(.plain)
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
                .foregroundStyle(Color(UIColor { t in
                    t.userInterfaceStyle == .dark
                        ? UIColor(red: 0x6e/255, green: 0xc9/255, blue: 0x7e/255, alpha: 1)
                        : UIColor(red: 0x3B/255, green: 0x6D/255, blue: 0x11/255, alpha: 1)
                }))
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
                if let data = try? vault.decryptContent(for: entry),
                   let str  = String(data: data, encoding: .utf8) {
                    UIPasteboard.general.string = str
                }
            } label: {
                actionButton("Copy", style: .standard)
            }
            .buttonStyle(.plain)

            NavigationLink {
                VaultShardSetup(entryID: entry.id)
            } label: {
                actionButton("Manage Shards", style: .primary)
            }
            .buttonStyle(.plain)

            Button { showDeleteAlert = true } label: {
                actionButton("Delete", style: .danger)
            }
            .buttonStyle(.plain)
        }
    }
}
