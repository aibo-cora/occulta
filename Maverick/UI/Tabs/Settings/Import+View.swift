//
//  Import+View.swift
//  Maverick
//
//  Created by Yura on 12/15/25.
//

import SwiftUI

struct Import: View {
    var document: Data
    
    @Environment(ContactManager.self) private var contactManager: ContactManager
    
    @State private var passphrase: String = ""
    @State private var porter = Manager.Porter()
    
    @Environment(\.dismiss) private var dismiss
    
    init(document: Data) {
        self.document = document
    }
    
    var body: some View {
        NavigationStack {
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
                        try self.contactManager.import(data: self.document, using: self.passphrase)
                        
                        self.dismiss()
                    } catch {
                        debugPrint("Could not import data.")
                    }
                } label: {
                    Text("Import Contacts")
                }
                .prominentButtonStyle()
                .disabled(self.passphrase.isEmpty)
            }
        }
    }
}

#Preview {
    Import(document: "Preview".data(using: .utf8)!)
        .environment(ContactManager.preview)
}
