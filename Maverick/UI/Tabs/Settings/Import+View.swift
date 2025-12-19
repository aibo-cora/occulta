//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI

struct Import: View {
    let message: Message
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    @State private var passphrase: String = ""
    @State private var porter = Manager.Porter()
    
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            switch self.message.format {
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
                            try self.contactManager.import(data: self.message.content, using: self.passphrase)
                            
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
                EmptyView()
            case .file:
                EmptyView()
            case .link:
                EmptyView()
            }
        }
    }
}

#Preview {
    Import(message: Message(origin: nil, recipients: nil, content: Data(), format: .text))
        .environment(ContactManager.preview)
}
