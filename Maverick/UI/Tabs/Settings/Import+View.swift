//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI

struct Import: View {
    let fileContents: File
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    @State private var passphrase: String = ""
    @State private var porter = Manager.Porter()
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            switch self.fileContents.format {
            case .contacts:
                VStack {
                    VStack {
                        Text("Enter the passphrase that was used to encrypt this file")
                        
                        TextField("Passphrase", text: self.$passphrase, prompt: Text("Required"))
                            .textFieldStyle(.roundedBorder)
                            .font(.custom("Courier", size: 20))
                    }
                    .padding()
                    
                    Button {
                        do {
                            try self.contactManager.import(data: self.fileContents.content, using: self.passphrase)
                            
                            self.dismiss()
                        } catch {
                            debugPrint("Could not import contacts: \(error).")
                        }
                    } label: {
                        Text("Import Contacts")
                    }
                    .prominentButtonStyle()
                    .disabled(self.passphrase.isEmpty)
                }
            case .text:
                /// We do not know at this point who the sender of the message is. We need to go through our contacts and try finding the right owner.
                if let result = try? self.contactManager.decrypt(message: self.fileContents.content) {
                    VStack {
                        Contact.Info(identifier: result.ownerID)
                        
                        Text(result.plaintext)
                    }
                } else {
                    Text("This message is not meant for you.")
                }
            case .document(_):
                EmptyView()
            case .link:
                EmptyView()
            case .none:
                EmptyView()
            }
        }
    }
}

extension Message {
    struct Decrypt: View {
        var body: some View {
            
        }
    }
}

#Preview {
    Import(fileContents: File(content: Data(), format: .contacts))
        .environment(ContactManager.preview)
}
