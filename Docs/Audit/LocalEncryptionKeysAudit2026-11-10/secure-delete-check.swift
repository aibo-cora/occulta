import Foundation
import CoreData
import SQLite3

// Standalone check, not Occulta code: does `PRAGMA secure_delete = ON`, set on a helper connection the way
// OccultaApp.applySecureDeletePragma does, scrub rows that Core Data (what SwiftData sits on) deletes later?
func run(helperPragma: Bool, blobSize: Int) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("store.sqlite")

    let entity = NSEntityDescription(); entity.name = "Row"; entity.managedObjectClassName = "NSManagedObject"
    let attr = NSAttributeDescription(); attr.name = "blob"; attr.attributeType = .binaryDataAttributeType; attr.isOptional = true
    entity.properties = [attr]
    let model = NSManagedObjectModel(); model.entities = [entity]

    let psc = NSPersistentStoreCoordinator(managedObjectModel: model)
    try! psc.addPersistentStore(ofType: NSSQLiteStoreType, configurationName: nil, at: url, options: nil)

    func exec(_ sql: String) {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else { return }
        defer { sqlite3_close(db) }
        sqlite3_exec(db, sql, nil, nil, nil)
    }
    if helperPragma { exec("PRAGMA secure_delete = ON") }

    let ctx = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
    ctx.persistentStoreCoordinator = psc
    let marker = Data("OCCULTAMARKER".utf8)
    var payload = Data(); while payload.count < blobSize { payload.append(marker) }
    ctx.performAndWait {
        for _ in 0..<60 { let o = NSManagedObject(entity: entity, insertInto: ctx); o.setValue(payload, forKey: "blob") }
        try! ctx.save()
    }
    exec("PRAGMA wal_checkpoint(TRUNCATE)")
    func count() -> Int {
        var n = 0
        for suffix in ["", "-wal"] {
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: url.path + suffix)) else { continue }
            var r = d.startIndex..<d.endIndex
            while let f = d.range(of: marker, in: r) { n += 1; r = f.upperBound..<d.endIndex }
        }
        return n
    }
    let before = count()
    ctx.performAndWait {
        let rows = try! ctx.fetch(NSFetchRequest<NSManagedObject>(entityName: "Row"))
        rows.forEach(ctx.delete)
        try! ctx.save()
    }
    exec("PRAGMA wal_checkpoint(TRUNCATE)")
    print("helper pragma \(helperPragma ? "ON " : "off"), blob \(blobSize) B: markers before delete \(before), after delete + TRUNCATE checkpoint \(count())")
}
run(helperPragma: true, blobSize: 9_000)
run(helperPragma: true, blobSize: 300)
run(helperPragma: false, blobSize: 9_000)
