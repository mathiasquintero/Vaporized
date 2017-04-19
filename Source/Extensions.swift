
import Foundation
import HTTP
import Turnstile
import Auth
import Vapor

infix operator <~: AssignmentPrecedence

public func <~<V>(_ variable: inout V?, _ value: V?) {
    guard let value = value else {
        return
    }
    variable = value
}

public func <~<V>(_ variable: inout V, _ value: V?) {
    guard let value = value else {
        return
    }
    variable = value
}

extension Date {

    static var now: Date {
        return Date()
    }

}

extension Date: NodeConvertible {

    public init(node: Node, in context: Context) throws {
        let double = try node.extract() as Double
        self.init(timeIntervalSince1970: double)
    }

    public func makeNode(context: Context) throws -> Node {
        return .number(.double(timeIntervalSince1970))
    }

}

extension Request {

    public var subject: Subject? {
        return storage["subject"] as? Subject
    }

}

extension RawRepresentable where RawValue: NodeConvertible {

    public init(node: Node, in context: Context) throws {
        let rawValue = try RawValue(node: node, in: context)
        guard let item = Self(rawValue: rawValue) else {
            throw NodeError.unableToConvert(node: node, expected: String(describing: Self.self))
        }
        self = item
    }

    public func makeNode(context: Context) throws -> Node {
        return try rawValue.makeNode(context: context)
    }

}

extension Request {

    public func token<Item: Authenticated>() throws -> Token<Item> {
        let subject = self.subject

        guard let details = subject?.authDetails else {
            throw AuthError.notAuthenticated
        }

        guard let user = details.account as? Token<Item> else {
            throw AuthError.invalidAccountType
        }

        return user
    }

    public func authenticated<Item: Authenticated>() throws -> Item {
        let token: Token<Item> = try self.token()
        return try token.user()
    }

}
