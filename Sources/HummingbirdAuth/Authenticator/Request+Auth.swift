import Hummingbird

extension HBRequest {
    public struct Auth {
        /// Login with type
        /// - Parameter auth: authentication details
        public func login<Auth: HBAuthenticatable>(_ auth: Auth) {
            var logins = self.loginCache ?? [:]
            logins[ObjectIdentifier(Auth.self)] = auth
            self.request.extensions.set(\.auth.loginCache, value: logins)
        }

        /// Logout type
        /// - Parameter auth: authentication type
        public func logout<Auth: HBAuthenticatable>(_: Auth.Type) {
            if var logins = self.loginCache {
                logins[ObjectIdentifier(Auth.self)] = nil
                self.request.extensions.set(\.auth.loginCache, value: logins)
            }
        }

        /// Return authenticated type
        /// - Parameter auth: Type required
        public func get<Auth: HBAuthenticatable>(_: Auth.Type) -> Auth? {
            return self.loginCache?[ObjectIdentifier(Auth.self)] as? Auth
        }

        /// Return if request is authenticated with type
        /// - Parameter auth: Authentication type
        public func has<Auth: HBAuthenticatable>(_: Auth.Type) -> Bool {
            return self.loginCache?[ObjectIdentifier(Auth.self)] != nil
        }

        /// cache of all the objects that have been logged in
        var loginCache: [ObjectIdentifier: HBAuthenticatable]? { self.request.extensions.get(\.auth.loginCache) }

        let request: HBRequest
    }

    /// Authentication interface
    public var auth: Auth { return .init(request: self) }
}
