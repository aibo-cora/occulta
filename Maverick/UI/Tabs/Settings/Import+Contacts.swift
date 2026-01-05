//
//  Import+Contacts.swift
//  Maverick
//
//  Created by Yura on 1/1/26.
//

import SwiftUI

extension Import {
    /// View with a passphrase prompt to decrypt contacts.
    struct Contacts: View {
        @Environment(ContactManager.self) private var contactManager: ContactManager
        
        let encryptedFile: EncryptedFile
        
        @State private var passphrase: String = ""
        @State private var imported: ImportedFile?
        @State private var displayingErrorDecryptingFile: Bool = false
        
        var body: some View {
            VStack {
                if let imported {
                    SelectContacts(imported: imported)
                        .transition(.move(edge: .bottom))
                        .animation(.easeInOut(duration: 0.5), value: imported)
                } else {
                    VStack(spacing: 20) {
                        Text("Enter the passphrase that was used to encrypt this file")
                        
                        TextField("Passphrase", text: self.$passphrase, prompt: Text("Required"))
                            .textFieldStyle(.roundedBorder)
                            .font(.custom("Courier", size: 20))
                        
                        Button {
                            withAnimation {
                                if let decrypted = try? self.contactManager.decrypt(data: self.encryptedFile.data, using: self.passphrase) {
                                    self.imported = ImportedFile(file: File(content: decrypted, format: .contacts), owner: "")
                                }
                            }
                        } label: {
                            Text("Decrypt File")
                        }
                        .prominentButtonStyle()
                        .disabled(self.passphrase.isEmpty)
                        
                        if self.displayingErrorDecryptingFile {
                            Text("Failed to decrypt the file. Please make sure the passphrase is correct and try again.")
                                .foregroundStyle(.red)
                        }
                    }
                    .padding()
                    .transition(.asymmetric(insertion: .move(edge: .bottom), removal: .move(edge: .top)))
                }
            }
        }
    }
}

#Preview {
    Import.Contacts(encryptedFile: EncryptedFile(id: UUID(), data: Data()))
        .environment(ContactManager.preview)
}
