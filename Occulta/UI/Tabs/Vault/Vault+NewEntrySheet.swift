//
//  Vault+NewEntrySheet.swift
//  Occulta
//

import SwiftUI

struct VaultNewEntrySheet: View {
    @Environment(VaultManager.self) private var vault
    @Environment(\.dismiss) private var dismiss

    @State private var selectedType: VaultEntryType = .seedPhrase
    @State private var label = ""
    @State private var content = ""
    @State private var error: String? = nil
    @State private var shardEntryID: UUID? = nil
    @State private var navigateToShards = false

    private var canSave: Bool {
        !self.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !self.content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Type picker
                    VStack(alignment: .leading, spacing: 8) {
                        self.monoLabel("Type")
                        LazyVGrid(
                            columns: Array(repeating: GridItem(.flexible()), count: 3),
                            spacing: 8
                        ) {
                            ForEach(VaultEntryType.allCases, id: \.self) { type in
                                self.typeTile(type)
                            }
                        }
                    }

                    // Details section
                    VStack(alignment: .leading, spacing: 8) {
                        self.monoLabel("Details")
                        VStack(alignment: .leading, spacing: 0) {
                            // Label field
                            VStack(alignment: .leading, spacing: 4) {
                                self.fieldLabel("Label")
                                TextField("", text: $label, prompt:
                                    Text("e.g. Ethereum Wallet")
                                        .font(.system(size: 13, design: .monospaced))
                                )
                                .font(.system(size: 13, design: .monospaced))
                                .tint(.occultaAccent)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)

                            Divider()

                            // Content field
                            VStack(alignment: .leading, spacing: 4) {
                                self.fieldLabel("Content")
                                ZStack(alignment: .topLeading) {
                                    if self.content.isEmpty {
                                        Text(self.selectedType == .seedPhrase
                                            ? "Enter seed phrase, one word per line…"
                                            : "Enter content…")
                                            .font(.system(size: 13, design: .monospaced))
                                            .foregroundStyle(.tertiary)
                                            .padding(.top, 8)
                                            .padding(.leading, 4)
                                            .allowsHitTesting(false)
                                    }
                                    TextEditor(text: $content)
                                        .font(.system(size: 13, design: .monospaced))
                                        .frame(minHeight: 100)
                                        .scrollContentBackground(.hidden)
                                        .tint(.occultaAccent)
                                        .privacySensitive(true)
                                }
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 10)
                        }
                        .background(Color(.secondarySystemGroupedBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }

                    if let error = self.error {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(Color.occultaDanger)
                    }

                    // Shamir CTA
                    Button { self.saveAndSetupShards() } label: {
                        HStack(spacing: 12) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(Color.white.opacity(0.2))
                                    .frame(width: 42, height: 42)
                                Text("🔮")
                                    .font(.system(size: 20))
                            }
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Create Shamir shards")
                                    .font(.system(size: 15, weight: .bold))
                                Text("split · distribute · recover")
                                    .font(.system(size: 10, design: .monospaced))
                                    .opacity(0.85)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.system(size: 14, weight: .semibold))
                                .opacity(0.8)
                        }
                        .foregroundStyle(.white)
                        .padding(14)
                        .background(self.canSave ? Color.occultaAccent : Color.secondary.opacity(0.50))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .shadow(color: self.canSave ? Color.occultaAccent.opacity(0.28) : .clear, radius: 8, y: 4)
                    }
                    .buttonStyle(.plain)
                    .disabled(!self.canSave)

                    Text("Content is encrypted with your SE key before being written to disk.")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                }
                .padding(16)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("New Entry")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { self.dismiss() }
                        .tint(.occultaAccent)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") { self.save() }
                        .tint(.occultaAccent)
                        .disabled(!self.canSave)
                }
            }
            .navigationDestination(isPresented: $navigateToShards) {
                if let id = self.shardEntryID {
                    VaultShardSetup(entryID: id)
                }
            }
        }
    }

    // MARK: - Type tile
    private func typeTile(_ type: VaultEntryType) -> some View {
        let selected = self.selectedType == type
        return Button { self.selectedType = type } label: {
            VStack(spacing: 6) {
                Text(type.emoji)
                    .font(.system(size: 24))
                Text(type.displayName)
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .lineLimit(2)
                    .foregroundStyle(selected ? type.tileTint : .secondary)
            }
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(selected
                          ? type.tileTint.opacity(0.12)
                          : Color(.secondarySystemGroupedBackground))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(
                                selected ? type.tileTint : Color.clear,
                                lineWidth: 1.5
                            )
                    )
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Helpers
    private func monoLabel(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundStyle(.secondary)
            .tracking(1.3)
    }

    private func fieldLabel(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundStyle(.tertiary)
            .tracking(1.2)
    }

    private func save() {
        self.error = nil
        do {
            let data = self.content.data(using: .utf8) ?? Data()
            _ = try self.vault.addEntry(label: self.label, content: data, type: self.selectedType)
            self.dismiss()
        } catch VaultManager.VaultError.locked {
            self.error = "Vault locked — unlock and try again."
        } catch {
            self.error = "Failed to save: \(error.localizedDescription)"
        }
    }

    private func saveAndSetupShards() {
        self.error = nil
        do {
            let data = self.content.data(using: .utf8) ?? Data()
            let entry = try self.vault.addEntry(label: self.label, content: data, type: self.selectedType)
            self.shardEntryID = entry.id
            self.navigateToShards = true
        } catch VaultManager.VaultError.locked {
            self.error = "Vault locked — unlock and try again."
        } catch {
            self.error = "Failed to save: \(error.localizedDescription)"
        }
    }
}
