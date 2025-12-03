//
//  Contact+Phone.swift
//  Maverick
//
//  Created by Yura on 12/3/25.
//

import SwiftUI

extension Contact {
    struct Phone: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(self.$contact.phoneNumbers) { $phone in
                    Row(phone: $phone) {
                        withAnimation {
                            self.deletePhone(phone)
                        }
                    }
                }
                
                Button {
                    withAnimation {
                        self.contact.phoneNumbers.append(Contact.Draft.PhoneNumber())
                    }
                } label: {
                    Label("Add phone number", systemImage: "plus.circle.fill")
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            .padding()
        }
        
        private func deletePhone(_ phone: Contact.Draft.PhoneNumber) {
            self.contact.phoneNumbers.removeAll { $0.id == phone.id }
        }
        
        struct Row: View {
            @Binding var phone: Contact.Draft.PhoneNumber
            
            var onDelete: () -> Void
            
            var body: some View {
                HStack(spacing: 12) {
                    Button(action: self.onDelete) {
                        Image(systemName: "minus.circle.fill")
                            .foregroundColor(.red)
                            .font(.title2)
                    }
                    .buttonStyle(.plain)
                    
                    Menu {
                        ForEach(Contact.Draft.PhoneNumber.PhoneType.allCases, id: \.self) { type in
                            Button {
                                self.phone.type = type
                            } label: {
                                Label(type.rawValue, systemImage: type.systemImage)
                            }
                        }
                    } label: {
                        Label(self.phone.type.rawValue, systemImage: self.phone.type.systemImage)
                            .foregroundColor(.primary)
                            .frame(maxWidth: 120, alignment: .leading)
                    }
                    .frame(width: 120)
                    
                    TextField("Phone number", text: self.$phone.value)
                        .keyboardType(.phonePad)
                        .textContentType(.telephoneNumber)
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
    Contact.Phone(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}

#Preview {
    Contact.Phone.Row(phone: .constant(Contact.Draft.PhoneNumber())) {
        
    }
}
