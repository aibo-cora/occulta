//
//  Welcome.swift
//  Maverick
//
//  Created by Yura on 10/13/25.
//

import SwiftUI

struct Welcome: View {
    @State private var generator = QRCode.Generator()
    @State private var code: QRCode?
    
    var body: some View {
        TabView {
            /// Welcome
            VStack(alignment: .leading, spacing: 30) {
                Text("Welcome to Maverick!")
                    .bold()
                
                Text("This application is designed to protect your privacy. Use it to store your keys and keys of your trusted contacts. There are no servers storing your data. The data is stored on your phone only, do not lose this device!")
                
                Text("Let us walk you through the features of this privacy focused application.")
                    
            }
            .padding(.horizontal)
            /// Share your key
            VStack() {
                Spacer()
                
                HStack {
                    Text("Share your key")
                        .bold()
                    Image(systemName: "qrcode")
                        .foregroundStyle(.blue)
                }
                .padding()
                
                Text("Share the public part of your key pair. People who have this key will be able to encrypt messages that only you can decrypt.")
                    .padding(.bottom, 25)
                
                VStack(alignment: .leading, spacing: 40) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.green)
                        
                        Text("The recommended way to share it is with someone who is physically present with you.")
                    }
                    
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                        
                        Text("Be mindful how you share this piece of information. If you use an untrusted environment, like SMS or email, to share it with another person, a malicious actor can intercept and replace it with another public key and later decrypt messages that were meant for you. If you choose to share it this way, we are going to ask you to confirm that you trust the contact.")
                    }
                }
                .padding(.bottom, 45)
                
                Spacer()
            }
            .padding(.horizontal)
            /// Create trusted contacts
            VStack {
                
            }
            /// Encrypt a message
            VStack {
                
            }
            /// Decrypt a message
            VStack {
                
            }
            /// Delete a contact
            VStack {
                
            }
            /// Delete everything
            VStack {
                Button {
                    
                } label: {
                    Text("Done")
                }
            }
        }
        .tabViewStyle(.page)
        .sheet(item: self.$code) { code in
            let qrCode = self.generator.generate(from: code.id)
            
            Image(uiImage: qrCode)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        }
    }
}

#Preview {
    Welcome()
}
