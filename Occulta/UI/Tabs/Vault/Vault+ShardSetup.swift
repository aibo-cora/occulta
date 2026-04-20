//
//  Vault+ShardSetup.swift
//  Occulta
//
//  Shard distribution setup: threshold slider + contact picker + distribute.
//  Calls VaultManager.prepareShards() to split and sign shards.
//  Delivery via .occ is a separate step outside this view.
//

import SwiftUI
import SwiftData

struct VaultShardSetup: View {
    let entryID: UUID

    @Environment(VaultManager.self) private var vault
    @Environment(\.dismiss) private var dismiss

    @Query(sort: \Contact.Profile.familyName) private var contacts: [Contact.Profile]

    @State private var selectedIDs:  Set<String> = []
    @State private var threshold     = 2
    @State private var distributing  = false
    @State private var error: String?

    private var recipients: [Contact.Profile] {
        contacts.filter { selectedIDs.contains($0.identifier) }
    }

    private var canDistribute: Bool {
        selectedIDs.count >= 2 && threshold <= selectedIDs.count
    }

    var body: some View {
        List {
            // Threshold
            Section {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(spacing: 12) {
                        Slider(
                            value: Binding(
                                get: { Double(threshold) },
                                set: { threshold = max(2, min(Int($0.rounded()), selectedIDs.count)) }
                            ),
                            in: 2...Double(max(2, selectedIDs.count)),
                            step: 1
                        )
                        .tint(.occultaAccent)
                        .disabled(selectedIDs.count < 2)

                        Text("\(threshold)/\(max(threshold, selectedIDs.count))")
                            .font(.system(size: 20, weight: .bold, design: .monospaced))
                            .foregroundStyle(Color.primary)
                            .frame(minWidth: 44, alignment: .trailing)
                    }

                    (Text("Any ")
                     + Text("\(threshold)").fontWeight(.bold).foregroundColor(.primary)
                     + Text(" contacts can help you recover. Fewer than ")
                     + Text("\(threshold)").fontWeight(.bold).foregroundColor(.primary)
                     + Text(" shards reveal nothing."))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineSpacing(3)
                }
                .padding(.vertical, 4)
            } header: {
                monoHeader("Threshold")
            }

            // Contact picker
            Section {
                if contacts.isEmpty {
                    Text("No contacts yet. Exchange keys first.")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(contacts) { contact in
                        contactRow(contact)
                    }
                }
            } header: {
                monoHeader("Recipients")
            } footer: {
                Text("Select ≥ 2 contacts. Each receives one signed shard via .occ.")
                    .font(.system(size: 11, design: .monospaced))
            }

            // Information-theoretic security note
            Section {
                HStack(alignment: .top, spacing: 8) {
                    Text("🔮")
                        .font(.system(size: 13))
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Information-theoretic security")
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                        Text("Any single shard carries zero information about your secret. An attacker with fewer than \(threshold) shards learns nothing. This is perfect secrecy over GF(2⁸), not computational hardness.")
                            .font(.system(size: 11, design: .monospaced))
                            .lineSpacing(3)
                    }
                    .foregroundStyle(Color(red: 0x3C/255, green: 0x34/255, blue: 0x89/255))
                }
                .padding(.vertical, 4)
                .listRowBackground(VaultEntryType.cat(light: (0xEE,0xED,0xFE), dark: (0x1e,0x1c,0x38)))
            }

            // Delivery info
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Delivery")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .tracking(1.2)
                    Text("Each shard is encrypted to the contact's verified public key and delivered as a signed .occ bundle via any channel.")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineSpacing(3)
                }
                .padding(.vertical, 4)
            }

            // Error
            if let error {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(Color.occultaDanger)
                        .listRowBackground(Color.clear)
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollIndicators(.hidden)
        .navigationTitle("Shards")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("Done") { dismiss() }
                    .tint(.occultaAccent)
            }
        }
        .safeAreaInset(edge: .bottom) {
            Button(action: distribute) {
                Group {
                    if distributing {
                        ProgressView().tint(.white)
                    } else {
                        Text("Distribute Shards")
                            .font(.system(size: 16, weight: .semibold))
                    }
                }
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(canDistribute ? Color.occultaAccent : .secondary.opacity(0.3))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .disabled(!canDistribute || distributing)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(.ultraThinMaterial)
        }
    }

    // MARK: - Contact row

    private func contactRow(_ contact: Contact.Profile) -> some View {
        let given    = contact.givenName.decrypt()
        let family   = contact.familyName.decrypt()
        let name     = [given, family].filter { !$0.isEmpty }.joined(separator: " ")
        let selected = selectedIDs.contains(contact.identifier)

        return Button {
            if selected {
                selectedIDs.remove(contact.identifier)
                threshold = max(2, min(threshold, selectedIDs.count))
            } else {
                selectedIDs.insert(contact.identifier)
            }
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(avatarGradientV2(for: contact.identifier))
                        .frame(width: 36, height: 36)
                    Text(name.initials)
                        .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.white)
                }

                Text(name.isEmpty ? contact.identifier : name)
                    .font(.system(size: 16))
                    .foregroundStyle(.primary)

                Spacer()

                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? Color.occultaAccent : .secondary)
                    .font(.system(size: 20))
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: - Helpers

    private func monoHeader(_ text: String) -> some View {
        Text(text.uppercased())
            .font(.system(size: 11, weight: .semibold, design: .monospaced))
            .tracking(1.6)
    }

    private func distribute() {
        distributing = true
        error = nil
        do {
            _ = try vault.prepareShards(
                for:        entryID,
                threshold:  threshold,
                recipients: recipients
            )
            dismiss()
        } catch VaultManager.VaultError.locked {
            error = "Vault locked — unlock and try again."
            distributing = false
        } catch {
            self.error = "Failed: \(error.localizedDescription)"
            distributing = false
        }
    }
}
