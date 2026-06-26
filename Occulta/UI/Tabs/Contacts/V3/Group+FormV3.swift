//
//  Group+FormV3.swift
//  Occulta
//

import SwiftUI
import SwiftData

extension Group {
    struct FormV3: View {

        enum FormMode {
            case create
            case edit(groupID: UUID)
        }

        let formMode: FormMode

        @State private var name = ""
        @Query private var groups: [Group]

        @Environment(\.dismiss)          private var dismiss
        @Environment(ContactManager.self) private var contactManager

        init(mode: FormMode = .create) {
            self.formMode = mode
        }

        private var existingGroup: Group? {
            guard case .edit(let id) = self.formMode else { return nil }
            return self.groups.first { $0.readID() == id }
        }

        private var isEditing: Bool {
            if case .edit = self.formMode { return true }
            return false
        }

        private var canSave: Bool {
            !self.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }

        var body: some View {
            NavigationStack {
                Form {
                    Section("NAME") {
                        TextField("Group name", text: self.$name)
                            .tint(Color.occultaAccent)
                    }
                }
                .navigationTitle(self.isEditing ? "Edit Group" : "New Group")
                .navigationBarTitleDisplayMode(.large)
                .onAppear {
                    if let grp = self.existingGroup {
                        self.name = grp.readName() ?? ""
                    }
                }
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Cancel", role: .cancel) { self.dismiss() }
                            .tint(Color.occultaAccent)
                    }
                    ToolbarItem(placement: .topBarTrailing) {
                        Button(self.isEditing ? "Save" : "Create") {
                            let trimmed = self.name.trimmingCharacters(in: .whitespacesAndNewlines)
                            
                            if let grp = self.existingGroup {
                                try? grp.writeName(trimmed)
                            } else {
                                _ = try? self.contactManager.createGroup(name: trimmed)
                            }
                            self.dismiss()
                        }
                        .tint(Color.occultaAccent)
                        .disabled(!self.canSave)
                    }
                }
            }
        }
    }
}
