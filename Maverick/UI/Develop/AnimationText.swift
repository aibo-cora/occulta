import SwiftUI

struct ExchangeResult: View {
    @State private var showingVerification = false
    @State var wordsMatch = false
    
    let receivedKeyingMaterial: Data
    
    var body: some View {
        VStack(spacing: 20) {
            
        }
        .task {
            withAnimation(.easeInOut(duration: 1).delay(5.0)) {
                self.showingVerification = true
            }
        }
        .sheet(isPresented: self.$showingVerification) {
            VStack {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text("Congrats, you successfully exchanged keys with your contact.")
                }
                .padding(.bottom)
                
                Divider()
                
                VStack {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                        Text("Please confirm bad guys did not swap your keys with their own. Verify with your contact that the words you are seeing match and are in the correct order.")
                            .foregroundStyle(.secondary)
                    }
                    .padding()
                    
                    VerifyExchangeWords()
                        .padding()
                }
            }
            .presentationDetents([.large])
        }
    }
}

struct VerifyExchangeWords: View {
    let passphraseGenerator = Manager.PassphraseGenerator()
    let keyManager = Manager.Key()
    
    @State private var beginAnimation = false
    
    var body: some View {
        VStack(spacing: 20) {
            let separator = "-"
            let passphrase = self.passphraseGenerator.generate(separator: separator)
            let components = passphrase.components(separatedBy: separator)
            
            ForEach(components, id: \.self) { word in
                Text(word)
                    .transition(.move(edge: .bottom))
                    .font(.custom("Courier", size: 20))
                    .bold()
            }
            
            Text("By confirming these words, you are agreeing to use this contact's key to encrypt data between you two.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            
            HStack {
                Button("Cancel", role: .destructive) {
                    
                }
                .prominentButtonStyle()
                .padding(.leading)
                
                Spacer()
                
                Button {
                    
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
    ExchangeResult(receivedKeyingMaterial: Data.randomBytes(32))
}
