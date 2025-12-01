//
//  Decrypt.swift
//  Maverick
//
//  Created by Yura on 12/2/25.
//

import SwiftUI

struct Decrypt: View {
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    @State private var decryptedTextToShow: String = ""
    
    let identifier: String
    
    var body: some View {
        VStack(spacing: 20) {
            Button {
                do {
                    let pastedTextToDecrypt = UIPasteboard.general.string ?? ""
                    let decrypted = try self.contactManager?.decrypt(message: pastedTextToDecrypt, for: self.identifier)
                    
                    self.decryptedTextToShow = decrypted ?? "No text was produced after decryption"
                } catch {
                    
                }
            } label: {
                Text("Paste From Clipboard")
            }
            .buttonStyle(.borderedProminent)
            
            if self.decryptedTextToShow.isEmpty == false {
                VStack(spacing: 10) {
                    Text("Decrypted Message")
                        .bold()
                    
                    Text(self.decryptedTextToShow)
                        .multilineTextAlignment(.leading)
                        .lineLimit(nil)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
