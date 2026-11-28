//
//  ReceivedImageFuzzTarget.swift
//  OccultaTests
//
//  The fuzz target for an image that came from a contact (`bugs.md` Bug 187, residual 2): a message attachment
//  shown in the message view, which goes through `AttachmentManager.thumbnail(of:)` after it is opened from its
//  sealed file. The bytes are the sender's, so what they declare is the sender's too.
//
//  The question is the usual one (does it trap, hang or balloon) and two more: a refusal must be the same error an
//  undecodable image gives, `invalidImageData`, since the bubble must not be able to tell them apart, and what is
//  drawn is never bigger than the thumbnail limit.
//

import Foundation
import ImageIO
import UniformTypeIdentifiers
import UIKit
@testable import Occulta

@MainActor
struct ReceivedImageTarget: MainActorFuzzTarget {
    let name = "AttachmentManager.thumbnail (a contact's image)"

    var corpus: [FuzzSeedInput] {
        var seeds: [FuzzSeedInput] = []
        for format in [UTType.jpeg, .png, .gif, .tiff] {
            if let image = ShareSessionTarget.image(as: format) { seeds.append(FuzzSeedInput("\(format.identifier) with metadata", image)) }
        }
        // What Bug 187 found, kept as seeds so mutation starts from the hostile shapes: the 79-byte PNG that declares a 2 GB
        // chunk, and a small file that declares 30,000 by 30,000 pixels. Neither may be drawn.
        seeds.append(FuzzSeedInput("png declaring a 2 GB chunk", ImageSizeRegressionTests.declares2GB, isValid: false))
        seeds.append(FuzzSeedInput("png declaring 900 megapixels", ImageSizeRegressionTests.png(width: 30_000, height: 30_000), isValid: false))
        seeds.append(FuzzSeedInput("well-formed png", ImageSizeRegressionTests.wellFormed))
        return seeds
    }

    func run(_ input: Data) throws {
        do {
            let image = try AttachmentManager.thumbnail(of: input)
            guard max(image.size.width * image.scale, image.size.height * image.scale) <= 960 else {
                throw FuzzViolation("a thumbnail of \(image.size) was drawn: the limit is 960 pixels a side")
            }
        } catch AttachmentError.invalidImageData {
            throw FuzzRejection()
        } catch let violation as FuzzViolation {
            throw violation
        } catch {
            throw FuzzViolation("a refused image gave \(error), not invalidImageData: the bubble would show it differently")
        }
    }
}
