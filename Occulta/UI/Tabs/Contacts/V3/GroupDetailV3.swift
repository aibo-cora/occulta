//
//  GroupDetailV3.swift
//  Occulta
//

import SwiftUI
import SwiftData

// MARK: - Group Detail V3

struct GroupDetailV3: View {
    let groupID: UUID

    @Query private var contacts: [Contact.Profile]
    @Query private var groups:   [Group]

    @Environment(ContactManager.self)   private var contactManager
    @Environment(Manager.Security.self) private var security
    @Environment(\.dismiss)             private var dismiss

    @State private var editing          = false
    @State private var useThreadCompose = false
    @State private var membersExpanded  = false
    @State private var composeVM        = ComposeViewModel(identifier: "")

    private var group: Group? {
        self.groups.first { $0.readID() == self.groupID }
    }

    private var resolvedMembers: [Contact.Profile] {
        guard let grp = self.group else { return [] }
        
        let layer       = RoutingDepth(rawValue: self.security.currentDepth) ?? .normal
        let identifiers = Set(grp.members(in: layer))

        return self.contacts.filter { identifiers.contains($0.identifier) && self.security.isDisplayable($0) }
    }

    var body: some View {
        let members = self.resolvedMembers
        let count   = members.count

        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                IdentityStripV3(
                    avatarID:  self.groupID.uuidString,
                    fullName:  self.group?.readName() ?? "",
                    subtitle:  "\(count) member\(count == 1 ? "" : "s")",
                    status:    nil,
                    thumbnail: nil
                )

                if count > 0 {
                    ComposeToggleV3(useThread: self.$useThreadCompose)

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
                        let gID = self.groupID
                        let ids = members.map { $0.identifier }
                        ComposeHeroV3(
                            vm:           self.composeVM,
                            headerRight:  "→ \(count) RECIPIENT\(count == 1 ? "" : "S")",
                            encryptLabel: "Encrypt for \(count)",
                            onEncrypt:    { await self.composeVM.encrypt(groupID: gID, recipients: ids, contactManager: cm) }
                        )
                    }

                    Text("Hybrid PQ · ML-KEM-1024")
                        .font(.system(size: 10, weight: .regular, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                }

                MembersDisclosureV3(members: members, expanded: self.$membersExpanded)
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
        .onChange(of: self.useThreadCompose) { _, _ in self.composeVM.clearAfterEncrypt() }
        .onDisappear { self.composeVM.cleanup() }
        .fullScreenCover(isPresented: self.$editing) {
            Group.FormV3(mode: .edit(groupID: self.groupID), onDelete: { self.dismiss() })
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
}

// MARK: - Members Disclosure

private struct MembersDisclosureV3: View {
    let members:  [Contact.Profile]
    @Binding var expanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) { self.expanded.toggle() }
            } label: {
                HStack {
                    Circle().fill(Color.occultaVerified).frame(width: 8, height: 8)
                    Text("Members")
                        .font(.system(size: 15))
                        .foregroundStyle(Color.primary)
                    Text("\(self.members.count)")
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(self.expanded ? 90 : 0))
                        .animation(.easeInOut(duration: 0.2), value: self.expanded)
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 11)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if self.expanded {
                Divider().padding(.leading, 14)
                ForEach(Array(self.members.enumerated()), id: \.element.id) { index, member in
                    MemberRowV3(profile: member)
                    if index < self.members.count - 1 {
                        Divider().padding(.leading, 66)
                    }
                }
            }
        }
        .background(Color(.secondarySystemGroupedBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

private struct MemberRowV3: View {
    let profile: Contact.Profile

    private var givenName:  String { self.profile.givenName.decrypt() }
    private var familyName: String { self.profile.familyName.decrypt() }
    private var fullName:   String {
        [self.givenName, self.familyName].filter { !$0.isEmpty }.joined(separator: " ")
    }

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                avatarGradientV2(for: self.profile.identifier)
                Text(self.fullName.initials)
                    .font(.system(size: 14, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
            }
            .frame(width: 40, height: 40)
            .clipShape(Circle())

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 0) {
                    Text(self.givenName.isEmpty ? "" : self.givenName + " ")
                        .font(.body)
                    Text(self.familyName)
                        .font(.body.weight(.semibold))
                }
                if let fp = self.profile.fingerprintPreview {
                    HStack(spacing: 5) {
                        Circle().fill(Color.occultaVerified).frame(width: 6, height: 6)
                        Text(fp)
                            .font(.system(size: 10, weight: .regular, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
    }
}
