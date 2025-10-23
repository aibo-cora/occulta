//
//  ContactCarousel.swift
//  Maverick
//
//  Created by Yura on 10/23/25.
//

import SwiftUI

struct ContactCarousel: View {
    @State private var thumbnails: [Thumbnail] = [
        Thumbnail(image: Image("green-lake")),
        Thumbnail(image: Image("lake-forest")),
        Thumbnail(image: Image("mountains")),
        Thumbnail(image: Image("redwood")),
        Thumbnail(image: Image("white-mountain"))
    ]
    
    var body: some View {
        NavigationStack {
            VStack {
                ScrollView(.horizontal) {
                    HStack {
                        ForEach(self.thumbnails) { thumbnail in
                            Button {
                                
                            } label: {
                                thumbnail.image
                                    .resizable()
                                    .aspectRatio(contentMode: .fill)
                                    .frame(width: 50, height: 50)
                                    .clipShape(Circle())
                                    .overlay(Circle().stroke(.red.opacity(0.4), lineWidth: 4))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding()
                }
                .scrollIndicators(.hidden)
                
                Text("Select a contact to communicate with")
                    .padding(.top)
                
                Spacer()
                    .navigationTitle("Contacts")
            }
        }
    }
}

#Preview {
    ContactCarousel()
}

struct Thumbnail: Identifiable {
    let id = UUID()
    let image: Image
}
