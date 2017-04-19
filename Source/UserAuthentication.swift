
import Turnstile
import TurnstileCrypto
import HTTP
import Foundation
import Auth
import Random
import Fluent
import Cache
import JSON

enum GrantType: String, NodeConvertible {
    case password
    case refreshToken = "refresh_token"
}

final class Token<UserType: Authenticated>: NodeConvertible, Credentials, Account, ResponseRepresentable {

    var uniqueID: String {
        return accountID.string ?? ""
    }

    let token: String
    let refreshToken: String
    let expirationDate: Date
    let scope: String
    let accountID: Node

    init(expiresIn: Int = UserType.tokenExpirationDefault, scope: String, accountID: Node) {
        token = URandom().secureToken
        refreshToken = URandom().secureToken
        expirationDate = Date.now.addingTimeInterval(Double(60 * expiresIn))
        self.scope = scope
        self.accountID = accountID
    }

    init(node: Node, in context: Context) throws {
        self.token = try node.extract("token")
        self.refreshToken = try node.extract("refreshToken")
        self.expirationDate = try node.extract("expirationDate")
        self.scope = try node.extract("scope")
        self.accountID = try node.extract("accountID")
    }

    func makeNode(context: Context) throws -> Node {
        return try Node(node: [
                "token": token,
                "refreshToken": refreshToken,
                "expirationDate": expirationDate,
                "scope": scope.makeNode(context: context),
                "accountID": accountID,
            ])
    }

    func makeResponse() throws -> Response {
        return try makeJSON().makeResponse()
    }

    func makeJSON() throws -> JSON {
        return try JSON(node: [
                "token_type" : "bearer",
                "token": token,
                "refresh_token": refreshToken,
                "expires_in": Int(expirationDate.timeIntervalSinceNow / 60)
            ])
    }

    func user() throws -> UserType {
        guard let user = try AuthenticatedUser<UserType>.authenticate(credentials: Identifier(id: accountID)) as? AuthenticatedUser<UserType> else {

            throw AuthError.invalidCredentials
        }
        return user.userData
    }

    func refresh(with refreshToken: String, expiration: Int) throws -> Token<UserType> {
        guard refreshToken == self.refreshToken else {
            throw AuthError.invalidCredentials
        }
        return Token(scope: scope, accountID: accountID)
    }

}

final class TokenRealm<UserType: Authenticated>: Realm {

    let cache: CacheProtocol

    init(cache: CacheProtocol) {
        self.cache = cache
    }

    func authenticate(credentials: Credentials) throws -> Account {
        switch credentials {
        case let id as Identifier:
            let refresh = id.id.string ?? ""
            guard let cache = try cache.get(refresh) else {
                throw AuthError.invalidCredentials
            }
            let token = try Token<UserType>(node: cache)
            return try token.refresh(with: refresh, expiration: 60)
        case let token as Token<UserType>:
            guard token.expirationDate > .now else {
                throw AuthError.invalidBearerAuthorization
            }
            return token
        default:
            throw AuthError.invalidCredentials
        }
    }

    func register(credentials: Credentials) throws -> Account {
        throw AuthError.unsupportedCredentials
    }

}

final class OAuthSessionManager<UserType: Authenticated>: SessionManager {

    private let cache: CacheProtocol
    let realm: Realm

    public init(cache: CacheProtocol) {
        self.cache = cache
        self.realm = TokenRealm<UserType>(cache: cache)
    }

    public func restoreAccount(fromSessionID identifier: String) throws -> Account {
        guard let cache = try cache.get(identifier) else {
            throw AuthError.invalidIdentifier
        }
        let token = try Token<UserType>(node: cache)
        return try realm.authenticate(credentials: token)
    }

    public func createSession(account: Account) -> String {
        guard let token = account as? Token<UserType> else {
            return ""
        }
        try? cache.set(token.token, token)
        try? cache.set(token.refreshToken, token)
        return token.token
    }

    public func destroySession(identifier: String) {
        let account = try? restoreAccount(fromSessionID: identifier)
        guard let token = account as? Token<UserType> else {
            return
        }
        try? cache.delete(token.token)
        try? cache.delete(token.refreshToken)
    }
}

class OAuthMiddleware<UserType: Authenticated>: Middleware {

    private let turnstile: Turnstile

    init(turnstile: Turnstile) {
        self.turnstile = turnstile
    }

    init() {
        let session = OAuthSessionManager<UserType>(cache: MemoryCache())
        turnstile = Turnstile(sessionManager: session, realm: session.realm)
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let token = request.auth.header?.bearer?.string.string
        request.storage["subject"] = Subject(turnstile: turnstile, sessionID: token)

        let response = try next.respond(to: request)

        return response
    }

}
