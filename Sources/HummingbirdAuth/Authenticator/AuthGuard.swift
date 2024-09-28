import Hummingbird

extension RouterMethods {
    public func authGuard<
        Guard: AuthenticatorGuardMiddleware
    >(
        _ authGuard: Guard
    ) -> RouterGroup<Guard.OutputContext> where Guard.InputContext == Context {
        group(middleware: authGuard)
    }

    public func authGuard<
        Guard: OptionalAuthenticatorMiddleware
    >(
        _ authGuard: Guard
    ) -> RouterGroup<
        MapToAuthenticatorGuardMiddleware<Guard.Value, Guard>.OutputContext
    > where Guard.InputContext == Context {
        group(middleware: authGuard.requireAuthentication())
    }
}
