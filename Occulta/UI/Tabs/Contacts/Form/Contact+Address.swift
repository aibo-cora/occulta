//
//  PostalAddress.swift
//  Occulta
//
//  Created by Yura on 12/4/25.
//


import SwiftUI

extension Contact {
    struct Address: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            VStack(alignment: .leading, spacing: 16) {
                ForEach(self.$contact.postalAddresses) { $address in
                    Row(address: $address) {
                        withAnimation {
                            self.deleteAddress(address)
                        }
                    }
                }
                
                Button {
                    withAnimation {
                        self.contact.postalAddresses.append(Contact.Draft.PostalAddress())
                    }
                } label: {
                    Label("Add address", systemImage: "plus.circle.fill")
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            .padding()
        }
        
        private func deleteAddress(_ address: Contact.Draft.PostalAddress) {
            self.contact.postalAddresses.removeAll { $0.id == address.id }
        }
        
        private struct Row: View {
            @Binding var address: Contact.Draft.PostalAddress
            
            var onDelete: () -> Void
            
            var body: some View {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Button(action: self.onDelete) {
                            Image(systemName: "minus.circle.fill")
                                .foregroundColor(.red)
                                .font(.title2)
                        }
                        .buttonStyle(.plain)
                        
                        Menu {
                            ForEach(Contact.Draft.PostalAddress.AddressType.allCases, id: \.self) { type in
                                Button {
                                    self.address.type = type
                                } label: {
                                    Label(type.rawValue, systemImage: type.systemImage)
                                }
                            }
                        } label: {
                            Label(self.address.type.rawValue, systemImage: self.address.type.systemImage)
                                .foregroundColor(.primary)
                        }
                        
                        Spacer()
                    }
                    
                    VStack(spacing: 15) {
                        TextField("Street address", text: self.$address.street)
                        
                        TextField("City", text: self.$address.city)
                        
                        TextField("State", text: self.$address.state)
                        
                        TextField("Postal Code", text: self.$address.postalCode)
                            .keyboardType(.numberPad)
                    }
                    
                    Menu {
                        ForEach(Contact.Draft.PostalAddress.Country.all) { country in
                            Button {
                                self.address.country = country
                            } label: {
                                HStack {
                                    Text(country.name)
                                }
                            }
                            .buttonStyle(.plain)
                        }
                    } label: {
                        HStack {
                            Text(self.address.country.flag)
                            Text(self.address.country.name)
                            
                            Spacer()
                            
                            Image(systemName: "chevron.up.chevron.down")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 10)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)
                    }
                }
                .padding()
                .background(Color(.secondarySystemBackground))
                .cornerRadius(12)
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .stroke(Color(.separator), lineWidth: 0.5)
                )
            }
        }
    }
}

// MARK: - Preview

#Preview {
    Contact.Address(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}
