import Hummingbird

/// Bearer authentication information extracted from request header "Authorization"
public struct BearerAuthentication {
    public let token: String
}

extension HBRequest.Auth {
    /// Return Bearer authorization information from request
    public var bearer: BearerAuthentication? {
        // check for authorization header
        guard let authorization = request.headers["Authorization"].first else { return nil }
        // check for bearer prefix
        guard authorization.hasPrefix("Bearer ") else { return nil }
        // return token
        return .init(token: String(authorization.dropFirst("Bearer ".count)))
    }
}
