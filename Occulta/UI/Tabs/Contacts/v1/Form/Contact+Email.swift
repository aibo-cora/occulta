import SwiftUI

extension Contact {
    struct Email: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(self.$contact.emailAddresses) { $email in
                    Row(email: $email) {
                        withAnimation {
                            self.deleteEmail(email)
                        }
                    }
                }
                
                Button {
                    withAnimation {
                        self.contact.emailAddresses.append(Contact.Draft.EmailAddress())
                    }
                } label: {
                    Label("Add email address", systemImage: "plus.circle.fill")
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            .padding()
        }
        
        private func deleteEmail(_ email: Contact.Draft.EmailAddress) {
            self.contact.emailAddresses.removeAll { $0.id == email.id }
        }
        
        struct Row: View {
            @Binding var email: Contact.Draft.EmailAddress
            
            var onDelete: () -> Void
            
            var body: some View {
                HStack(spacing: 12) {
                    Button(action: onDelete) {
                        Image(systemName: "minus.circle.fill")
                            .foregroundColor(.red)
                            .font(.title2)
                    }
                    .buttonStyle(.plain)
                    
                    Menu {
                        ForEach(Contact.Draft.EmailAddress.EmailType.allCases, id: \.self) { type in
                            Button {
                                self.email.type = type
                            } label: {
                                Label(type.rawValue, systemImage: type.systemImage)
                            }
                        }
                    } label: {
                        Label(self.email.type.rawValue, systemImage: self.email.type.systemImage)
                            .foregroundColor(.primary)
                            .frame(maxWidth: 120, alignment: .leading)
                    }
                    .frame(width: 120)
                    
                    TextField("Email address", text: self.$email.value)
                        .keyboardType(.emailAddress)
                        .textContentType(.emailAddress)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)
                }
                .padding(.vertical, 4)
            }
        }
    }
}

#Preview {
    Contact.Email(contact: .constant(Contact.Draft(identifier: UUID().uuidString)), )
}
