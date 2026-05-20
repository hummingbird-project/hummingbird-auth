//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Hummingbird
import HummingbirdAuth
import HummingbirdTesting
import Testing

// MARK: - Test identity

/// Identity used across all authorization tests.
/// Conforms to both ``RoleProviding`` and ``PermissionProviding`` so that
/// ``RolePolicy``, ``PermissionPolicy``, and their combinations can all be
/// exercised with a single type.
private struct User: Sendable, RoleProviding, PermissionProviding {
    let name: String
    var roles: Set<String>
    var permissions: Set<String>

    init(name: String, roles: Set<String> = [], permissions: Set<String> = []) {
        self.name = name
        self.roles = roles
        self.permissions = permissions
    }
}

// MARK: - Tests

struct AuthorizationTests {

    // MARK: AuthorizationPolicyMiddleware — HTTP status codes

    @Test func testAuthorizationPolicyMiddlewareAllows() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            // Authenticator always succeeds — sets context.identity
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "admin", roles: ["admin"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test func testAuthorizationPolicyMiddlewareForbids() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "guest", roles: ["user"])  // authenticated but wrong role
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    @Test func testAuthorizationPolicyMiddlewareRequiresAuthentication() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            // No authenticator — context.identity is nil
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .unauthorized)
            }
        }
    }

    @Test func testAuthorizationPolicyMiddlewareCustomError() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)

        // Default: 403 Forbidden
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "guest", roles: ["user"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("default-error") { _, _ -> HTTPResponse.Status in .ok }

        // Override: 404 Not Found — hides resource existence from unauthorised callers
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "guest", roles: ["user"])
                }
            )
            .add(
                middleware: AuthorizationPolicyMiddleware(
                    RolePolicy("admin"),
                    deniedError: HTTPError(.notFound)
                )
            )
            .get("hidden-resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/default-error", method: .get) { response in
                #expect(response.status == .forbidden)
            }
            try await client.execute(uri: "/hidden-resource", method: .get) { response in
                #expect(response.status == .notFound)
            }
        }
    }

    // MARK: ClosureAuthorizationPolicy

    @Test func testClosureAuthorizationPolicy() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "alice")
                }
            )
            .add(
                middleware: AuthorizationPolicyMiddleware(
                    ClosureAuthorizationPolicy { user, request in
                        // Allow only requests whose "user" query param matches the identity name
                        user.name == request.uri.queryParameters.get("user")
                    }
                )
            )
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource?user=alice", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/resource?user=bob", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: AllOf combinator

    @Test func testAllOfPassesWhenAllPoliciesPass() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "editor", roles: ["editor", "verified"])
                }
            )
            .authorized {
                RolePolicy("editor")
                RolePolicy("verified")
            }
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test func testAllOfFailsWhenAnyPolicyFails() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "editor", roles: ["editor"])  // missing "verified"
                }
            )
            .authorized {
                RolePolicy("editor")
                RolePolicy("verified")
            }
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: AnyOf combinator

    @Test func testAnyOfPassesWhenOnePolicyPasses() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "mod", roles: ["moderator"])  // no "admin" but has "moderator"
                }
            )
            .authorized {
                anyOf(RolePolicy("admin"), RolePolicy("moderator"))
            }
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .ok)
            }
        }
    }

    @Test func testAnyOfFailsWhenNoPolicyPasses() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "guest", roles: ["user"])  // neither admin nor moderator
                }
            )
            .authorized {
                anyOf(RolePolicy("admin"), RolePolicy("moderator"))
            }
            .get("resource") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/resource", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: Not combinator

    @Test func testNotInverts() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)

        // Route 1: user without "banned" role → allowed
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "alice", roles: ["user"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(Not(RolePolicy("banned"))))
            .get("allowed") { _, _ -> HTTPResponse.Status in .ok }

        // Route 2: banned user → forbidden
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "mallory", roles: ["banned"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(Not(RolePolicy("banned"))))
            .get("denied") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/allowed", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/denied", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: RolePolicy

    @Test func testRolePolicy() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "admin", roles: ["admin"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("admin") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "guest", roles: ["user"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(RolePolicy("admin")))
            .get("no-access") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/admin", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/no-access", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: PermissionPolicy

    @Test func testPermissionPolicy() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "publisher", permissions: ["posts:publish"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(PermissionPolicy("posts:publish")))
            .get("publish") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "reader", permissions: ["posts:read"])
                }
            )
            .add(middleware: AuthorizationPolicyMiddleware(PermissionPolicy("posts:publish")))
            .get("no-publish") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/publish", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/no-publish", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: anyOf mixing roles and permissions

    @Test func testAnyOfMixedRoleAndPermission() async throws {
        // anyOf(RolePolicy, PermissionPolicy) — A.Identity == B.Identity holds
        // because both RolePolicy<User> and PermissionPolicy<User> share Identity = User.
        // User conforms to both RoleProviding and PermissionProviding.
        let router = Router(context: BasicAuthRequestContext<User>.self)

        // Route: admin role OR posts:delete permission grants access
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "admin", roles: ["admin"], permissions: [])
                }
            )
            .authorized {
                anyOf(RolePolicy("admin"), PermissionPolicy("posts:delete"))
            }
            .delete("post") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    // moderator with delete permission but no admin role
                    User(name: "mod", roles: ["moderator"], permissions: ["posts:delete"])
                }
            )
            .authorized {
                anyOf(RolePolicy("admin"), PermissionPolicy("posts:delete"))
            }
            .delete("post-mod") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    // reader: no admin role, no delete permission
                    User(name: "reader", roles: ["user"], permissions: ["posts:read"])
                }
            )
            .authorized {
                anyOf(RolePolicy("admin"), PermissionPolicy("posts:delete"))
            }
            .delete("post-reader") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            // admin role satisfies anyOf
            try await client.execute(uri: "/post", method: .delete) { response in
                #expect(response.status == .ok)
            }
            // posts:delete permission satisfies anyOf
            try await client.execute(uri: "/post-mod", method: .delete) { response in
                #expect(response.status == .ok)
            }
            // neither role nor permission — denied
            try await client.execute(uri: "/post-reader", method: .delete) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: Role + Permission composition

    @Test func testRoleAndPermissionComposition() async throws {
        let router = Router(context: BasicAuthRequestContext<User>.self)

        // Has role + permission → allowed
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "alice", roles: ["editor"], permissions: ["posts:publish"])
                }
            )
            .authorized {
                RolePolicy("editor")
                PermissionPolicy("posts:publish")
            }
            .get("can-publish") { _, _ -> HTTPResponse.Status in .ok }

        // Has role but not permission → forbidden
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "bob", roles: ["editor"], permissions: ["posts:read"])
                }
            )
            .authorized {
                RolePolicy("editor")
                PermissionPolicy("posts:publish")
            }
            .get("no-permission") { _, _ -> HTTPResponse.Status in .ok }

        // Has permission but not role → forbidden
        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "charlie", roles: ["user"], permissions: ["posts:publish"])
                }
            )
            .authorized {
                RolePolicy("editor")
                PermissionPolicy("posts:publish")
            }
            .get("no-role") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/can-publish", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/no-permission", method: .get) { response in
                #expect(response.status == .forbidden)
            }
            try await client.execute(uri: "/no-role", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }

    // MARK: Deep composition

    @Test func testDeepComposition() async throws {
        // (admin OR (editor AND posts:publish)) AND NOT banned
        let router = Router(context: BasicAuthRequestContext<User>.self)

        // nested anyOf/allOf need one <User> anchor on the first element of each inner block
        // to give Swift's constraint solver the Identity it can't propagate backwards
        // (admin OR (editor AND posts:publish)) AND NOT banned
        // Two-arg anyOf/allOf avoid the circular-inference issue of nested builders
        router.group()
            .add(middleware: ClosureAuthenticator { _, _ in User(name: "admin", roles: ["admin"]) })
            .authorized {
                anyOf(
                    RolePolicy("admin"),
                    allOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
                )
                Not(RolePolicy("banned"))
            }
            .get("admin") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "editor", roles: ["editor"], permissions: ["posts:publish"])
                }
            )
            .authorized {
                anyOf(
                    RolePolicy("admin"),
                    allOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
                )
                Not(RolePolicy("banned"))
            }
            .get("editor") { _, _ -> HTTPResponse.Status in .ok }

        router.group()
            .add(
                middleware: ClosureAuthenticator { _, _ in
                    User(name: "banned-admin", roles: ["admin", "banned"])
                }
            )
            .authorized {
                anyOf(
                    RolePolicy("admin"),
                    allOf(RolePolicy("editor"), PermissionPolicy("posts:publish"))
                )
                Not(RolePolicy("banned"))
            }
            .get("banned") { _, _ -> HTTPResponse.Status in .ok }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/admin", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/editor", method: .get) { response in
                #expect(response.status == .ok)
            }
            try await client.execute(uri: "/banned", method: .get) { response in
                #expect(response.status == .forbidden)
            }
        }
    }
}
