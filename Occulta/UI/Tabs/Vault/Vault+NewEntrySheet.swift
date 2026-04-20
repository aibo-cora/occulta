//
//  Vault+NewEntrySheet.swift
//  Occulta
//
//  Bottom sheet for adding a new vault entry.
//  Type picker → label → content → save.
//

import SwiftUI

struct VaultNewEntrySheet: View {
    @Environment(VaultManager.self) private var vault
    @Environment(\.dismiss) private var dismiss

    @State private var selectedType: VaultEntryType = .seedPhrase
    @State private var label   = ""
    @State private var content = ""
    @State private var error: String?
    @State private var shardEntryID:    UUID? = nil
    @State private var navigateToShards = false

    private var canSave: Bool {
        !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        && !content.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Type picker
                    VStack(alignment: .leading, spacing: 8) {
                        monoLabel("Type")
                        LazyVGrid(
                            columns: Array(repeating: GridItem(.flexible()), count: 3),
                            spacing: 8
                        ) {
                            ForEach(VaultEntryType.allCases, id: \.self) { type in
                                typeTile(type)
                            }
                        }
                    }

                    // Label
                    VStack(alignment: .leading, spacing: 6) {
                        monoLabel("Label")
                        TextField("e.g. Ethereum Wallet", text: $label)
                            .padding(12)
                            .background(Color(.secondarySystemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                            .tint(.occultaAccent)
                    }

                    // Content
                    VStack(alignment: .leading, spacing: 6) {
                        monoLabel("Content")
                        TextEditor(text: $content)
                            .font(.system(size: 13, design: .monospaced))
                            .frame(minHeight: 100)
                            .padding(8)
                            .background(Color(.secondarySystemGroupedBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                            .tint(.occultaAccent)
                    }

                    if let error {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(Color.occultaDanger)
                    }

                    // Shamir CTA — saves then pushes shard setup
                    Button { saveAndSetupShards() } label: {
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
                        .background(canSave ? Color.occultaAccent : Color.secondary.opacity(0.35))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .shadow(color: canSave ? Color.occultaAccent.opacity(0.28) : .clear, radius: 8, y: 4)
                    }
                    .buttonStyle(.plain)
                    .disabled(!canSave)

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
                    Button("Cancel") { dismiss() }
                        .tint(.occultaAccent)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") { save() }
                        .tint(.occultaAccent)
                        .disabled(!canSave)
                }
            }
            .navigationDestination(isPresented: $navigateToShards) {
                if let id = shardEntryID {
                    VaultShardSetup(entryID: id)
                }
            }
        }
    }

    // MARK: - Type tile

    private func typeTile(_ type: VaultEntryType) -> some View {
        let selected = selectedType == type
        return Button { selectedType = type } label: {
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

    private func save() {
        error = nil
        do {
            let data = content.data(using: .utf8) ?? Data()
            _ = try vault.addEntry(label: label, content: data, type: selectedType)
            dismiss()
        } catch VaultManager.VaultError.locked {
            error = "Vault locked — unlock and try again."
        } catch {
            self.error = "Failed to save: \(error.localizedDescription)"
        }
    }

    private func saveAndSetupShards() {
        error = nil
        do {
            let data  = content.data(using: .utf8) ?? Data()
            let entry = try vault.addEntry(label: label, content: data, type: selectedType)
            shardEntryID    = entry.id
            navigateToShards = true
        } catch VaultManager.VaultError.locked {
            error = "Vault locked — unlock and try again."
        } catch {
            self.error = "Failed to save: \(error.localizedDescription)"
        }
    }
}
