
import Vapor
import Fluent
import HTTP

public protocol Applyable {
    static var preparations: [Preparation.Type] { get }
    static func apply(to drop: Droplet)
}

extension Applyable where Self: Preparation {

    public static var preparations: [Preparation.Type] {
        return [Self.self]
    }

}

public protocol Model: Vapor.Model, JSONInitializable, Preparation, Applyable {
    static var uriComponent: String { get }
    static var controller: Controller<Self> { get }
    mutating func override(with request: Request) throws
    func shouldPerform(request: Request, of type: ItemRequestType) throws -> Bool
    static func shouldPerform(request: Request, of type: ModelRequestType) throws -> Bool
}

public enum ModelRequestType {
    case index
    case create
    case clear
}

public enum ItemRequestType {
    case show
    case delete
    case update
}

extension Model {

    public static var uriComponent: String {
        let name = String(describing: Self.self)
        return "\(name.lowercased())s"
    }

    public static var controller: Controller<Self> {
        return Controller()
    }

    public func shouldPerform(request: Request, of type: ItemRequestType) throws -> Bool {
        return true
    }

    public static func shouldPerform(request: Request, of type: ModelRequestType) throws -> Bool {
        return true
    }

    public static func prepare(_ database: Database) throws {
        try database.create(uriComponent) { collection in
            collection.id()
        }
    }

    public static func revert(_ database: Database) throws {
        try database.delete(uriComponent)
    }

    public static func apply(to drop: Droplet) {
        controller.apply(to: drop)
    }

}

open class Controller<ModelType: Model>: ResourceRepresentable {

    public func index(request: Request) throws -> ResponseRepresentable {
        guard try ModelType.shouldPerform(request: request, of: .index) else {
            throw Abort.serverError
        }
        return try ModelType.all().makeJSON()
    }

    public func create(request: Request) throws -> ResponseRepresentable {
        guard try ModelType.shouldPerform(request: request, of: .create) else {
            throw Abort.serverError
        }
        var post: ModelType = try request.model()
        try post.save()
        return post
    }

    public func show(request: Request, item: ModelType) throws -> ResponseRepresentable {
        guard try item.shouldPerform(request: request, of: .show) else {
            throw Abort.serverError
        }
        return item
    }

    public func delete(request: Request, item: ModelType) throws -> ResponseRepresentable {
        guard try item.shouldPerform(request: request, of: .delete) else {
            throw Abort.serverError
        }
        try item.delete()
        return JSON([:])
    }

    public func clear(request: Request) throws -> ResponseRepresentable {
        guard try ModelType.shouldPerform(request: request, of: .clear) else {
            throw Abort.serverError
        }
        try ModelType.query().delete()
        return JSON([])
    }

    public func update(request: Request, item: ModelType) throws -> ResponseRepresentable {
        guard try item.shouldPerform(request: request, of: .update) else {
            throw Abort.serverError
        }
        var item = item
        try item.override(with: request)
        try item.save()
        return item
    }

    public func replace(request: Request, item: ModelType) throws -> ResponseRepresentable {
        return try update(request: request, item: item)
    }

    public func makeResource() -> Resource<ModelType> {
        return Resource(
            index: index,
            store: create,
            show: show,
            replace: replace,
            modify: update,
            destroy: delete,
            clear: clear
        )
    }

    public func apply(to drop: Droplet) {
        drop.resource(ModelType.uriComponent, self)
    }

}

extension Request {

    public func model<V: Model>() throws -> V {
        guard let json = json else { throw Abort.badRequest }
        return try V(json: json)
    }

}

extension Droplet {

    public func add(types: Applyable.Type...) {
        add(types: types)
    }

    public func add(types: [Applyable.Type]) {
        preparations.append(contentsOf: types.flatMap { $0.preparations })
        types.forEach { type in
            type.apply(to: self)
        }
    }

}
