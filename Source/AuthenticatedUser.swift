
import Foundation
import Vapor
import Fluent
import Auth
import HTTP
import Turnstile
import TurnstileCrypto
import TurnstileWeb

final class AuthenticationController<UserType: Authenticated>: Controller<UserType> {

    override func apply(to drop: Droplet) {
        super.apply(to: drop)
        let auth = OAuthMiddleware<UserType>()
        drop.middleware.append(auth)
        drop.post("login", handler: UserType.login)
    }

}

public protocol Authenticated: Model {
    static var tokenExpirationDefault: Int { get }
}

extension Authenticated {
    
    static var tokenExpirationDefault: Int {
        return 60
    }

    static var preparations: [Preparation.Type] {
        return [Self.self, AuthenticatedUser<Self>.self]
    }

    static var controller: Controller<Self> {
        return AuthenticationController<Self>()
    }

    static func passwordLogin(form: Node) throws -> Token<Self> {
        let credentials = APIKey(id: try form.extract("username"), secret: try form.extract("password"))
        let user = try AuthenticatedUser<Self>.authenticate(credentials: credentials)
        guard let id = user.id else {
            throw AuthError.unsupportedCredentials
        }
        return Token<Self>(expiresIn: tokenExpirationDefault, scope: try form.extract("scope"), accountID: id)
    }

    static func login(request: Request) throws -> ResponseRepresentable {
        guard let form = request.formURLEncoded else {
            throw Abort.badRequest
        }
        let grantType: GrantType = try form.extract("grant_type")
        switch grantType {
        case .password:
            let token = try passwordLogin(form: form)
            try request.auth.login(token)
            return token
        case .refreshToken:
            guard let refreshToken: String = try form.extract("refresh_token") else {
                throw AuthError.invalidCredentials
            }
            try request.auth.login(Identifier(id: refreshToken))
            return try request.token() as Token<Self>
        }
    }

    @discardableResult mutating func register(email: String, password: String) throws -> AuthenticatedUser<Self> {
        try save()
        do {
            return try .register(user: self, email: email, password: password)
        } catch {
            try delete()
            throw error
        }
    }

    func shouldPerform(request: Request, of type: ItemRequestType) throws -> Bool {
        let item = try request.authenticated() as Self
        return item.id == id
    }

}

final class AuthenticatedUser<UserType: Model>: Model {

    var id: Node?
    let email: String
    let password: String
    let salt: BCryptSalt
    var exists = false

    var userData: UserType

    init(email: String, password: String, userData: UserType) throws {
        salt = BCryptSalt()
        self.email = email
        self.password = BCrypt.hash(password: password, salt: salt)
        self.userData = userData

        guard try AuthenticatedUser<UserType>.query().filter("email", email).first() == nil else {

            throw Abort.custom(status: .conflict, message: "There's already a user with that email")
        }

    }

    init(node: Node, in context: Context) throws {
        id = try node.extract("id")
        salt = try BCryptSalt(string: try node.extract("salt"))
        email = try node.extract("email")
        password = try node.extract("password")
        let userID: Node = try node.extract("userID")
        guard let user = try UserType.find(userID) else {
            throw AuthError.unsupportedCredentials
        }
        userData = user
    }

    @discardableResult static func register(user: UserType, email: String, password: String) throws -> AuthenticatedUser<UserType> {
        var authenticated = try AuthenticatedUser<UserType>(email: email, password: password, userData: user)
        try authenticated.save()
        return authenticated
    }

    func makeNode(context: Context) throws -> Node {
        return try Node(node: [
            "id": id,
            "salt": salt.string,
            "userID": userData.id,
            "email": email,
            "password": password,
            ])
    }

    func shouldPerform(request: Request, of type: ItemRequestType) throws -> Bool {
        return false
    }

    func override(with request: Request) throws {
        // DO Nothing
    }

}

extension AuthenticatedUser: Auth.User {

    static var uriComponent: String {
        return "\(UserType.uriComponent)-security"
    }

    static func authenticate(credentials: Credentials) throws -> Auth.User {
        switch credentials {
        case let id as Identifier:
            guard let user = try AuthenticatedUser<UserType>.find(id.id) else {
                throw Abort.custom(status: .forbidden, message: "Invalid Login")
            }
            return user
        case let credentials as APIKey:
            guard let matchingUser = try AuthenticatedUser<UserType>.query().filter("email", credentials.id).first(),
                BCrypt.hash(password: credentials.secret, salt: matchingUser.salt) == matchingUser.password else {

                    throw Abort.custom(status: .forbidden, message: "Invalid Login")
            }
            return matchingUser
        default:
            throw Abort.badRequest
        }
    }

    static func register(credentials: Credentials) throws -> Auth.User {
        throw Abort.badRequest
    }

}
