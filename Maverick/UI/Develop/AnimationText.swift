import SwiftUI
import CryptoKit

struct ExchangeResult: View {
    let identifier: String
    let receivedKeyingMaterial: Data
    
    private let testingData: Data = Data([
        0x9A, 0xF3, 0x4B, 0x2D, 0xE7, 0xC1, 0x88, 0x56,
        0x12, 0x9E, 0xA4, 0xF0, 0x7B, 0x33, 0xC5, 0xD9,
        0x64, 0x1F, 0x8D, 0xB2, 0xA0, 0xE5, 0x77, 0xC9,
        0x3E, 0x6A, 0xB1, 0xF4, 0x05, 0x92, 0xD8, 0x4C
    ])
    
    var body: some View {
        VStack {
            VStack(spacing: 20) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.title)
                Text("Congrats, you successfully exchanged keys with your contact.")
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal)
            
            Divider()
            
            VStack(spacing: 20) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.yellow)
                    Text("Please confirm bad guys did not swap your keys with their own. Verify with your contact that the words you are seeing match and are in the correct order.")
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                
                VerifyExchangeWords(identifier: self.identifier, keyingMaterial: self.receivedKeyingMaterial)
            }
        }
        .presentationDetents([.large])
    }
}

struct VerifyExchangeWords: View {
    let passphraseGenerator = Manager.PassphraseGenerator()
    let keyManager = Manager.Key()
    
    let identifier: String
    let keyingMaterial: Data
    
    @State private var beginAnimation = false
    
    @Environment(ContactManager.self) private var contactManager: ContactManager?
    
    var body: some View {
        VStack() {
            let sharedKeyingMaterial = self.keyManager.createSharedSecret(using: self.keyingMaterial)?.withUnsafeBytes { Data($0) }
            let separator = "-"
            let passphrase = self.passphraseGenerator.generate(separator: separator, sharedKey: sharedKeyingMaterial)
            let components = passphrase.components(separatedBy: separator)
            
            VStack(spacing: 20) {
                ForEach(components, id: \.self) { word in
                    Text(word)
                        .transition(.move(edge: .bottom))
                        .font(.custom("Courier", size: 20))
                        .bold()
                }
            }
            
            Text("By confirming these words, you are agreeing to use this contact's key to encrypt data between you two.")
                .font(.footnote)
                .padding()
            
            HStack {
                Button("Cancel", role: .destructive) {
                    
                }
                .prominentButtonStyle()
                .padding(.leading)
                
                Spacer()
                
                Button {
                    do {
                        try self.contactManager?.update(identity: self.keyingMaterial, for: self.identifier)
                    } catch {
                        
                    }
                } label: {
                    Text("Confirm")
                }
                .prominentButtonStyle()
                .padding([.trailing])
            }
        }
        .task {
            withAnimation(.easeIn(duration: 5.0).delay(5.0)) {
                self.beginAnimation = true
            }
        }
    }
}

#Preview {
    ExchangeResult(identifier: UUID().uuidString, receivedKeyingMaterial: Data.randomBytes(32))
}
