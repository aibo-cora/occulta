//
//  Website.swift
//  Occulta
//
//  Created by Yura on 12/4/25.
//


import SwiftUI

extension Contact {
    struct URLAddress: View {
        @Binding var contact: Contact.Draft
        
        var body: some View {
            VStack(alignment: .leading, spacing: 16) {
                ForEach(self.$contact.urlAddresses) { $website in
                    Row(website: $website) {
                        withAnimation { self.deleteWebsite(website) }
                    }
                }
                
                Button {
                    withAnimation {
                        self.contact.urlAddresses.append(Contact.Draft.URLAddress())
                    }
                } label: {
                    Label("Add website or profile", systemImage: "plus.circle.fill")
                        .foregroundColor(.blue)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .buttonStyle(.plain)
            }
            .padding()
        }
        
        private func deleteWebsite(_ website: Contact.Draft.URLAddress) {
            self.contact.urlAddresses.removeAll { $0.id == website.id }
        }
        
        private struct Row: View {
            @Binding var website: Contact.Draft.URLAddress
            
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
                        ForEach(Contact.Draft.URLAddress.WebsiteType.allCases, id: \.self) { type in
                            Button {
                                self.website.type = type
                            } label: {
                                Label(type.rawValue, systemImage: type.systemImage)
                            }
                        }
                    } label: {
                        Label(self.website.type.rawValue, systemImage: self.website.type.systemImage)
                            .foregroundColor(.primary)
                            .frame(width: 130, alignment: .leading)
                    }
                    .frame(width: 130)
                    
                    TextField(self.website.type.placeholder, text: self.$website.value)
                        .keyboardType(.URL)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)        }
                        .padding(.vertical, 4)
            }
        }
    }
}

// MARK: - Single URL Row


#Preview {
    Contact.URLAddress(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}
