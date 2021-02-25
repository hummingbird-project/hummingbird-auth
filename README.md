# Hummingbird Auth

Authentication framwork and extensions for Hummingbird server framework.

## Authenticators

Authenticators are middleware that are used to check if a request is authenticated and then augment the request with the authentication data. Authenticators should conform to protocol `HBAuthenticator`. This requires you implement the function `authenticate(request: HBRequest) -> EventLoopFuture<Value?>` where `Value` is an object conforming to the protocol `HBAuthenticatable`.

A simple username, password authenticator could be implemented as follows. If the authenticator is successful it returns a `User` struct, otherwise it returns `nil`.
```swift
struct BasicAuthenticator: HBAuthenticator {
    func authenticate(request: HBRequest) -> EventLoopFuture<User?> {
        // Basic authentication info in the "Authorization" header, is accessible
        // via request.auth.basic
        guard let basic = request.auth.basic else { return request.success(nil) }

        // check if user exists in the database and then verify the entered password
        // against the one stored in the database. If it is correct then login in user
        return database.getUserWithUsername(basic.username).map { user -> User? in
            // did we find a user
            guard let user = user else { return nil }
            // verify password against password hash stored in database. If valid
            // return the user. HummingbirdAuth provides an implementation of Bcrypt
            if Bcrypt.verify(basic.password, hash: user.passwordHash) {
                return user
            }
            return nil
        }
        // hop back to request eventloop
        .hop(to: request.eventLoop)
    }
}
```

Then in your request handler you can access your authentication data with `request.auth.get`.
```swift
/// Get current logged in user
func current(_ request: HBRequest) throws -> User {
    // get authentication data for user. If it doesnt exist then throw unauthorized error
    guard let user = request.auth.get(User.self) else { throw HBHTTPError(.unauthorized) }
    return user
}
```

## Documentation

You can find reference documentation for HummingbirdAuth [here](https://hummingbird-project.github.io/hummingbird/current/hummingbird-auth/index.html). The [hummingbird-examples](https://github.com/hummingbird-project/hummingbird-examples) repository has a number of examples of different uses of the library.
