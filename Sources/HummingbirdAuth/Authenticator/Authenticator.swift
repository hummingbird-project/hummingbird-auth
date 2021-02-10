import Hummingbird
import NIO

/// Protocol for objects that can be returned by an `HBAuthenticator`.
public protocol HBAuthenticatable {}

/// Middleware for authenticating requests
public protocol HBAuthenticator: HBMiddleware {
    /// type to be authenticated
    associatedtype Value: HBAuthenticatable
    /// Called by middleware to see if request is authenticated.
    ///
    /// Should return an authenticatable object if authenticated, return nil is not authenticated
    /// but want the request to be passed onto the next middleware or the router, or return a
    /// failed `EventLoopFuture` if the request should not proceed any further
    func authenticate(request: HBRequest) -> EventLoopFuture<Value?>
}

extension HBAuthenticator {
    /// Call `authenticate` and if it returns a valid autheniticatable object `login` with this
    /// object
    ///
    /// - Parameters:
    ///   - request: <#request description#>
    ///   - next: <#next description#>
    /// - Returns: <#description#>
    public func apply(to request: HBRequest, next: HBResponder) -> EventLoopFuture<HBResponse> {
        authenticate(request: request)
            .flatMap { authenticated in
                if let authenticated = authenticated {
                    request.auth.login(authenticated)
                }
                return next.respond(to: request)
            }
    }
}
