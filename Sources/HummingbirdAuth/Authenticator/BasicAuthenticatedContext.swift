import Hummingbird

public struct BasicOptionalAuthenticationContext<Subject: Authenticatable>: RequestContext {
    public typealias Source = Never

    public var coreContext: CoreRequestContextStorage
    public var currentUser: Subject?

    public init(baseContext: some RequestContext, currentUser: Subject?) {
        self.coreContext = baseContext.coreContext
        self.currentUser = currentUser
    }
}

public struct BasicAuthenticatedContext<Subject: Authenticatable>: RequestContext {
    public typealias Source = Never

    public var coreContext: CoreRequestContextStorage
    public var currentUser: Subject

    public init(baseContext: some RequestContext, currentUser: Subject) {
        self.coreContext = baseContext.coreContext
        self.currentUser = currentUser
    }
}
