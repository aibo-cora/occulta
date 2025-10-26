//
//  ContactCarousel.swift
//  Maverick
//
//  Created by Yura on 10/23/25.
//

import SwiftUI

struct ContactCarousel: View {
    @State private var thumbnails: [Thumbnail] = [
        Thumbnail(name: "green-lake"),
        Thumbnail(name: "lake-forest"),
        Thumbnail(name: "mountains"),
        Thumbnail(name: "redwood"),
        Thumbnail(name: "white-mountain")
    ]
    
    @State private var selected: Thumbnail? = Thumbnail(name: "green-lake")
    
    var body: some View {
        if let selected {
            VStack {
                Button {
                    self.selected = nil
                } label: {
                    Text("Done")
                }
                .buttonStyle(.borderedProminent)
                
                selected.image
                    .resizable()
                    .aspectRatio(contentMode: .fill)
                    .frame(width: 50, height: 50)
                    .clipShape(Circle())
                    .overlay(Circle().stroke(.red.opacity(0.4), lineWidth: 4))
                
            }
        } else {
            NavigationStack {
                VStack {
                    ScrollView(.horizontal) {
                        HStack {
                            ForEach(self.thumbnails) { thumbnail in
                                VStack {
                                    Button {
                                        self.selected = thumbnail
                                    } label: {
                                        thumbnail.image
                                            .resizable()
                                            .aspectRatio(contentMode: .fill)
                                            .frame(width: 50, height: 50)
                                            .clipShape(Circle())
                                            .overlay(Circle().stroke(.red.opacity(0.4), lineWidth: 4))
                                    }
                                    .buttonStyle(.plain)
                                    
                                    Text(thumbnail.name)
                                        .frame(width: 100)
                                        .lineLimit(2)
                                }
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
}

#Preview {
    ContactCarousel()
}

struct Thumbnail: Identifiable {
    let id = UUID()
    let name: String
    let image: Image
    
    init(name: String) {
        self.name = name
        self.image = Image(name)
    }
}
