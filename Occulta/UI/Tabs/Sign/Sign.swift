//
//  Signature.swift
//  Occulta
//
//  Created by Yura on 12/21/25.
//

import SwiftUI


struct Sign: View {
    @State private var text: String = ""
    @State private var mode: Mode = .message
    
    @State private var displayingInfo: Bool = false
    
    private enum Mode: Hashable {
        case message, document
    }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack {
                    Picker(selection: self.$mode) {
                        Text("Message")
                            .tag(Mode.message)
                        
                        Text("Document")
                            .tag(Mode.document)
                    } label: {
                        Label {
                            Text("Encryption Mode")
                        } icon: {
                            Image(systemName: "lock")
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding()
                    
                    switch self.mode {
                    case .message:
                        TextEditor(text: self.$text)
                            .foregroundStyle(.secondary)
                            .frame(height: 200)
                            .border(Color.gray, width: 1)
                            .padding()
                        
                        VStack(spacing: 20) {
                            HStack {
                                Text("Signature")
                                
                                Button {
                                    self.displayingInfo.toggle()
                                } label: {
                                    Image(systemName: "info.bubble")
                                }
                            }
                            
                            if self.displayingInfo {
                                Text("We use your **private** key to sign. Contacts with your **public** key will be able to verify this signature to make sure your message was not altered or fabricated by someone else.")
                                    .font(.footnote)
                                    .padding(.horizontal)
                                    .foregroundStyle(.secondary)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        
                        if self.text.isEmpty == false {
                            VStack {
                                let crypto: CryptoProtocol = Manager.Crypto()
                                
                                HStack {
                                    Button("Copy", systemImage: "doc.on.doc", role: .cancel) {
                                        let signature = crypto.sign(data: self.text.data(using: .utf8)).uppercased()
                                        let signedMessage = self.text + "\n\n\n" + "MavSig: \(signature)"
                                        
                                        UIPasteboard.general.string = signedMessage
                                    }
                                    .prominentButtonStyle()
                                    
                                    Button("Reset", systemImage: "arrow.counterclockwise", role: .destructive) {
                                        self.text = ""
                                    }
                                    .prominentButtonStyle()
                                }
                                .padding(.top)
                            }
                        }
                    case .document:
                        Text("Coming Soon...")
                            .padding()
                    }
                    
                    Spacer()
                }
                .navigationTitle("Sign")
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
        }
    }
}

#Preview {
    Sign()
}
