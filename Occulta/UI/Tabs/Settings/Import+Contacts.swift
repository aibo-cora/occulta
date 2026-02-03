//
//  Import+Contacts.swift
//  Occulta
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
        @State private var imported: OwnedBasket?
        @State private var displayingErrorDecryptingFile: Bool = false
        
        var body: some View {
            VStack {
                if let imported {
                    Import.DisplayImportedContactList(files: imported.basket.files)
                } else {
                    VStack(spacing: 20) {
                        Text("Enter the passphrase that was used to encrypt this file")
                        
                        TextField("Passphrase", text: self.$passphrase, prompt: Text("Required"))
                            .textFieldStyle(.roundedBorder)
                            .font(.custom("Courier", size: 20))
                        
                        Button {
                            withAnimation {
                                do {
                                    let decrypted = try self.contactManager.decrypt(data: self.encryptedFile.content, using: self.passphrase)
                                    let basket = try JSONDecoder().decode(Basket.self, from: decrypted)
                                    let owned = OwnedBasket(basket: basket, owner: "")
                                    
                                    self.imported = owned
                                } catch {
                                    debugPrint("Error decrypting basket or decoding = \(error)")
                                    
                                    self.displayingErrorDecryptingFile = true
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
                }
            }
            .transition(.opacity)
            .animation(.easeInOut(duration: 1.0), value: self.imported)
        }
    }
}

#Preview {
    Import.Contacts(encryptedFile: EncryptedFile(id: UUID(), content: Data()))
        .environment(ContactManager.preview)
}
