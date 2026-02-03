//
//  ContactPhoto.swift
//  Occulta
//
//  Created by Yura on 12/3/25.
//

import SwiftUI
import PhotosUI

extension Contact {
    struct Photo: View {
        @State var selectedPhotoItem: PhotosPickerItem?
        
        @Binding var contact: Contact.Draft
        
        var body: some View {
            PhotosPicker(selection: self.$selectedPhotoItem, matching: .images) {
                VStack {
                    Group {
                        if let imageData = self.contact.thumbnailImageData,
                           let uiImage = UIImage(data: imageData) {
                            Image(uiImage: uiImage)
                                .resizable()
                                .scaledToFill()
                                .clipShape(Circle())
                        } else {
                            Image(systemName: "person.crop.circle.fill")
                                .resizable()
                                .foregroundStyle(.gray.opacity(0.6))
                        }
                    }
                    .frame(width: 200, height: 200)
                    
                    Text("Add Photo")
                }
            }
            .onChange(of: self.selectedPhotoItem) { _, newItem in
                Task {
                    if let data = try? await newItem?.loadTransferable(type: Data.self) {
                        self.contact.imageData = data
                        
                        if let image = UIImage(data: data),
                           let thumbnail = image.preparingThumbnail(of: CGSize(width: 120, height: 120)) {
                            self.contact.thumbnailImageData = thumbnail.jpegData(compressionQuality: 0.8)
                        }
                    }
                }
            }
        }
    }
}

#Preview {
    Contact.Photo(contact: .constant(Contact.Draft(identifier: UUID().uuidString)))
}
