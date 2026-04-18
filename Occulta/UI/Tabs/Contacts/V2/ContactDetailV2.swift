//
//  ContactDetailV2.swift
//  Occulta
//

import SwiftUI
import SwiftData

extension Contact {
    struct DetailsV2: View {
        let identifier: String

        @Query private var contacts: [Contact.Profile]
        @Environment(ContactManager.self) private var contactManager
        @Environment(\.dismiss) private var dismiss

        @State private var editing = false
        @State private var keyDetailsExpanded = false
        @State private var displayingVerificationInfo = false

        init(identifier: String) {
            self.identifier = identifier
            self._contacts = Query(filter: #Predicate { $0.identifier == identifier })
        }

        private var profile: Contact.Profile? { contacts.first }

        private var givenName:  String { profile?.givenName.decrypt() ?? "" }
        private var familyName: String { profile?.familyName.decrypt() ?? "" }
        private var fullName:   String { [givenName, familyName].filter { !$0.isEmpty }.joined(separator: " ") }
        private var org:        String { profile?.organizationName.decrypt() ?? "" }
        private var jobTitle:   String { profile?.jobTitle.decrypt() ?? "" }
        private var subtitle:   String { [jobTitle, org].filter { !$0.isEmpty }.joined(separator: " · ") }

        private var needsExchange: Bool {
            let keys = profile?.contactPublicKeys
            return (keys?.isEmpty ?? true) || keys?.last?.expiredOn != nil
        }

        private var status: VerificationStatus { profile?.verificationStatus ?? .pending }

        var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    IdentityStripV2(
                        identifier: identifier,
                        fullName: fullName,
                        subtitle: subtitle,
                        status: status,
                        thumbnail: profile?.imageData?.decrypt() ?? profile?.thumbnailImageData?.decrypt()
                    )

                    if needsExchange {
                        ExchangeHeroV2(identifier: identifier)
                    } else {
                        ComposeHeroV2(identifier: identifier, firstName: givenName)

                        Text(profile?.encryptionSchemeLabel ?? "")
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .center)

                        if let p = profile {
                            KeyDetailsDisclosureV2(profile: p, expanded: $keyDetailsExpanded)
                        }
                    }

                    ContactInfoSectionV2(profile: profile)

                    if status == .unverified {
                        UnverifiedNoticeV2(expanded: $displayingVerificationInfo)
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
                    Menu {
                        Button { editing = true } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        NavigationLink {
                            KeyExchange(identifier: identifier)
                        } label: {
                            Label("Re-exchange key", systemImage: "key.horizontal.fill")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .fullScreenCover(isPresented: $editing) {
                Contact.FormV2(mode: .edit(identifier: identifier)) { dismiss() }
            }
        }
    }
}

// MARK: - Identity Strip

private struct IdentityStripV2: View {
    let identifier: String
    let fullName: String
    let subtitle: String
    let status: VerificationStatus
    let thumbnail: Data?

    var body: some View {
        HStack(spacing: 14) {
            Group {
                if let data = thumbnail, let img = UIImage(data: data) {
                    Image(uiImage: img).resizable().scaledToFill()
                } else {
                    ZStack {
                        avatarGradientV2(for: identifier)
                        Text(fullName.initials)
                            .font(.system(size: 18, weight: .semibold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                }
            }
            .frame(width: 52, height: 52)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 3) {
                Text(fullName)
                    .font(.system(size: 19, weight: .bold))
                    .tracking(-0.4)
                    .lineLimit(1)

                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            StatusChipV2(status: status)
        }
    }
}

// MARK: - Status Chip

private struct StatusChipV2: View {
    let status: VerificationStatus

    var body: some View {
        Text(status.chipLabel)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .tracking(1.2)
            .foregroundStyle(status == .pending ? AnyShapeStyle(.secondary) : AnyShapeStyle(.white))
            .padding(.horizontal, 9)
            .padding(.vertical, 4)
            .background(
                Group {
                    if status == .pending {
                        RoundedRectangle(cornerRadius: 4)
                            .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [3, 2]))
                            .foregroundStyle(.secondary)
                    } else {
                        RoundedRectangle(cornerRadius: 4).fill(status.color)
                    }
                }
            )
    }
}

// MARK: - Compose Hero

private struct ComposeHeroV2: View {
    let identifier: String
    let firstName: String

    @Environment(ContactManager.self) private var contactManager
    @State private var messageText = ""
    @State private var encryptedURL: URL?
    @State private var isShowingError = false
    @State private var errorMessage = ""

    private var ciphertextEstimate: Int { max(256, messageText.count * 4 + 256) }
    private var canEncrypt: Bool { !messageText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Encrypt a message").font(.body.bold())
                Spacer()
                Text("→ TO \(firstName.uppercased())")
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .padding(.bottom, 10)

            TextField("", text: $messageText, axis: .vertical)
                .lineLimit(4...)
                .frame(minHeight: 100, alignment: .topLeading)
                .tint(.occultaAccent)

            Divider().padding(.top, 10)

            HStack {
                HStack(spacing: 6) {
                    Circle().fill(Color.occultaVerified).frame(width: 6, height: 6)
                    Text("ciphertext · \(ciphertextEstimate) bytes")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: encrypt) {
                    Text("Encrypt")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(canEncrypt ? .white : .secondary)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 7)
                        .background(Capsule().fill(canEncrypt ? Color.occultaAccent : Color(.tertiarySystemFill)))
                }
                .disabled(!canEncrypt)
                .buttonStyle(.plain)
            }
            .padding(.top, 10)
        }
        .padding(14)
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .sheet(item: $encryptedURL) { url in ActivityView(activityItems: [url]) }
        .alert("Error", isPresented: $isShowingError) {
            Button("OK") { }
        } message: {
            Text(errorMessage)
        }
    }

    private func encrypt() {
        let text = self.messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        Task {
            do {
                let file    = Occulta.File(content: text.data(using: .utf8), format: .text, date: Date())
                let basket  = Basket(files: [file])
                let encoded = try JSONEncoder().encode(basket)
                let encrypted = try self.contactManager.encryptBundle(data: encoded, for: self.identifier)
                
                guard
                    encrypted.isEmpty == false
                else {
                    self.showError("Encryption failed. Try again.")
                    return
                }
                
                let name = UUID().uuidString.components(separatedBy: "-").last ?? "msg"
                let url  = FileManager.default.temporaryDirectory.appendingPathComponent("\(name).occ")
                try encrypted.write(to: url)
                
                await MainActor.run { self.encryptedURL = url }
            } catch {
                self.showError(error.localizedDescription)
            }
        }
    }

    @MainActor
    private func showError(_ message: String) {
        errorMessage = message
        isShowingError = true
    }
}

// MARK: - Exchange Hero

private struct ExchangeHeroV2: View {
    let identifier: String

    var body: some View {
        VStack(spacing: 16) {
            HStack(spacing: 14) {
                RoundedRectangle(cornerRadius: 4)
                    .strokeBorder(.white.opacity(0.6), lineWidth: 1.5)
                    .frame(width: 40, height: 40)
                    .overlay(Image(systemName: "key.horizontal.fill").foregroundStyle(.white.opacity(0.9)))

                VStack(alignment: .leading, spacing: 3) {
                    Text("No key yet")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(.white)
                    Text("exchange to encrypt messages")
                        .font(.system(size: 11, weight: .regular, design: .monospaced))
                        .foregroundStyle(.white.opacity(0.7))
                }
                Spacer()
            }

            HStack(spacing: 12) {
                // Show my QR (placeholder — QR flow wired in edit sheet)
                Button { } label: {
                    Text("Show my QR")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Capsule().fill(.white.opacity(0.2)))
                }
                .buttonStyle(.plain)

                NavigationLink {
                    KeyExchange(identifier: identifier)
                } label: {
                    Text("Scan theirs")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(Color.occultaAccent)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(Capsule().fill(.white))
                }
            }
        }
        .padding(14)
        .background(Color.occultaAccent)
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

// MARK: - Key Details Disclosure

private struct KeyDetailsDisclosureV2: View {
    let profile: Contact.Profile
    @Binding var expanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { expanded.toggle() }
            } label: {
                HStack {
                    Text("KEY DETAILS")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .tracking(1.6)
                    Spacer()
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(spacing: 0) {
                    KeyDetailRow(label: "FP",     value: profile.fingerprintFull ?? "—")
                    Divider().padding(.leading, 64)
                    KeyDetailRow(label: "SCHEME", value: profile.encryptionSchemeLabel)
                    Divider().padding(.leading, 64)
                    KeyDetailRow(label: "SINCE",  value: profile.exchangedDateLabel)
                }
                .padding(.bottom, 4)
            } else if let fp = profile.fingerprintPreview {
                Text(fp)
                    .font(.system(size: 10, weight: .regular, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .padding(.horizontal, 14)
                    .padding(.bottom, 12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

private struct KeyDetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label)
                .font(.system(size: 10, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .leading)
            Text(value)
                .font(.system(size: 11, weight: .regular, design: .monospaced))
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }
}

// MARK: - Contact Info Section

private struct ContactInfoSectionV2: View {
    let profile: Contact.Profile?

    private var phones: [(label: String, value: String)] {
        (profile?.phoneNumbers ?? []).compactMap {
            let v = $0.value.decrypt()
            return v.isEmpty ? nil : ($0.label.decrypt().uppercased(), v)
        }
    }

    private var emails: [(label: String, value: String)] {
        (profile?.emailAddresses ?? []).compactMap {
            let v = $0.value.decrypt()
            return v.isEmpty ? nil : ($0.label.decrypt().uppercased(), v)
        }
    }

    var body: some View {
        if !phones.isEmpty || !emails.isEmpty {
            VStack(alignment: .leading, spacing: 8) {
                Text("CONTACT")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .tracking(1.6)
                    .padding(.leading, 4)

                VStack(spacing: 0) {
                    ForEach(phones.indices, id: \.self) { i in
                        if i > 0 { Divider().padding(.leading, 76) }
                        ContactInfoRowV2(
                            label: phones[i].label,
                            value: phones[i].value,
                            url: URL(string: "tel:\(phones[i].value.filter { !$0.isWhitespace })")
                        )
                    }
                    if !phones.isEmpty && !emails.isEmpty {
                        Divider().padding(.leading, 76)
                    }
                    ForEach(emails.indices, id: \.self) { i in
                        if i > 0 { Divider().padding(.leading, 76) }
                        ContactInfoRowV2(
                            label: emails[i].label,
                            value: emails[i].value,
                            url: URL(string: "mailto:\(emails[i].value)")
                        )
                    }
                }
                .background(Color(.secondarySystemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }
}

private struct ContactInfoRowV2: View {
    let label: String
    let value: String
    let url: URL?

    var body: some View {
        HStack(spacing: 12) {
            Text(label)
                .font(.system(size: 10, weight: .regular, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .leading)
            if let url {
                Link(value, destination: url)
                    .foregroundStyle(Color.occultaAccent)
                    .lineLimit(1)
            } else {
                Text(value).lineLimit(1)
            }
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

// MARK: - Unverified Notice

private struct UnverifiedNoticeV2: View {
    @Binding var expanded: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Button {
                    withAnimation { expanded.toggle() }
                } label: {
                    Image(systemName: "info.bubble").foregroundStyle(Color.occultaWarn)
                }
                Text("This contact's key is not verified.")
                    .font(.footnote)
                    .foregroundStyle(Color.occultaWarn)
            }

            if expanded {
                Text("Not being verified means that this contact was shared with you or transferred from another device. You can encrypt data for the contact, but since we did not do the key exchange on this device, we cannot guarantee who the owner of the key is. In the future, when this contact is in vicinity, revoke this key in the **Edit** mode and do another key exchange to verify identity.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .background(Color.occultaWarn.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

#Preview {
    NavigationStack {
        Contact.DetailsV2(identifier: UUID().uuidString)
            .environment(ContactManager.preview)
    }
}
