//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Hummingbird
import HummingbirdAuth
import HummingbirdTesting
import Testing

// MARK: - Shared test identity

private struct User: Sendable {
    let name: String
}

// MARK: - Shared scope helper

/// Scope backed by an explicit allow-list per user name.
/// Stands in for any actual backend (OPA list, Casbin enforcement, ReBAC store query).
private struct AllowListScope: AuthorizationScope {
    typealias Identity = User
    typealias Filter = ClosureQueryFilter<String>

    let allowed: [String: Set<String>]

    func filter(for identity: User, request: Request) async throws -> ClosureQueryFilter<String> {
        let ids = allowed[identity.name] ?? []
        return ClosureQueryFilter { ids.contains($0) }
    }
}

// MARK: - Tests

struct ScopeTests {

    // MARK: QueryFilter

    @Test func testClosureQueryFilterMatchesPredicate() async throws {
        let filter = ClosureQueryFilter<String> { s in s.hasPrefix("pub-") }
        #expect(try await filter.matches("pub-doc") == true)
        #expect(try await filter.matches("pub-report") == true)
        #expect(try await filter.matches("private-doc") == false)
        #expect(try await filter.matches("") == false)
    }

    @Test func testClosureQueryFilterPropagatesThrows() async throws {
        struct FilterError: Error {}
        let filter = ClosureQueryFilter<String> { _ in throw FilterError() }
        await #expect(throws: FilterError.self) {
            _ = try await filter.matches("any")
        }
    }

    // MARK: AuthorizationScope

    @Test func testScopeFiltersCollectionPerIdentity() async throws {
        let scope = AllowListScope(allowed: [
            "editor": ["doc-1", "doc-2"],
            "admin":  ["doc-1", "doc-2", "doc-3"],
        ])
        let allItems = ["doc-1", "doc-2", "doc-3", "doc-other"]

        let router = Router(context: BasicAuthRequestContext<User>.self)

        router.group()
            .add(middleware: ClosureAuthenticator { _, _ in User(name: "editor") })
            .get("editor/items") { request, context -> [String] in
                guard let identity = context.identity else { throw HTTPError(.unauthorized) }
                let filter = try await scope.filter(for: identity, request: request)
                var result: [String] = []
                for item in allItems { if try await filter.matches(item) { result.append(item) } }
                return result.sorted()
            }

        router.group()
            .add(middleware: ClosureAuthenticator { _, _ in User(name: "admin") })
            .get("admin/items") { request, context -> [String] in
                guard let identity = context.identity else { throw HTTPError(.unauthorized) }
                let filter = try await scope.filter(for: identity, request: request)
                var result: [String] = []
                for item in allItems { if try await filter.matches(item) { result.append(item) } }
                return result.sorted()
            }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/editor/items", method: .get) { response in
                #expect(response.status == .ok)
                let items = try JSONDecoder().decode([String].self, from: response.body)
                #expect(items == ["doc-1", "doc-2"])
            }
            try await client.execute(uri: "/admin/items", method: .get) { response in
                #expect(response.status == .ok)
                let items = try JSONDecoder().decode([String].self, from: response.body)
                #expect(items == ["doc-1", "doc-2", "doc-3"])
            }
        }
    }

    @Test func testScopeReturnsEmptyForUnknownIdentity() async throws {
        let scope = AllowListScope(allowed: [:])
        let allItems = ["doc-1", "doc-2"]

        let router = Router(context: BasicAuthRequestContext<User>.self)
        router.group()
            .add(middleware: ClosureAuthenticator { _, _ in User(name: "stranger") })
            .get("items") { request, context -> [String] in
                guard let identity = context.identity else { throw HTTPError(.unauthorized) }
                let filter = try await scope.filter(for: identity, request: request)
                var result: [String] = []
                for item in allItems { if try await filter.matches(item) { result.append(item) } }
                return result
            }

        let app = Application(responder: router.buildResponder())
        try await app.test(.router) { client in
            try await client.execute(uri: "/items", method: .get) { response in
                #expect(response.status == .ok)
                let items = try JSONDecoder().decode([String].self, from: response.body)
                #expect(items.isEmpty)
            }
        }
    }
}
