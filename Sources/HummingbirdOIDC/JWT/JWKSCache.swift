//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import AsyncHTTPClient
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import JWTKit
import Logging
import NIOCore
import NIOFoundationCompat

/// Fetches, caches, and refreshes a JWKS from a remote URL.
///
/// - Lazily fetches on first use
/// - Refreshes when `kid` is not found (handles key rotation)
/// - Serialises concurrent refresh requests so only one in-flight fetch runs at a time
public actor JWKSCache {
    private var keyCollection: JWTKeyCollection
    private var fetchedAt: Date?
    private var fetchTask: Task<JWTKeyCollection, Error>?
    private let jwksURL: String
    private let cacheTTL: Duration
    private let httpClient: HTTPClient
    private let logger: Logger

    public init(
        jwksURL: String,
        cacheTTL: Duration,
        httpClient: HTTPClient,
        logger: Logger = Logger(label: "hummingbird-oidc.jwks")
    ) {
        self.jwksURL = jwksURL
        self.cacheTTL = cacheTTL
        self.httpClient = httpClient
        self.logger = logger
        self.keyCollection = JWTKeyCollection()
    }

    /// Returns a key collection, refreshing if necessary.
    ///
    /// - Parameter forceRefresh: When true, always re-fetch (e.g. after an unknown `kid`).
    public func keyCollection(forceRefresh: Bool = false) async throws -> JWTKeyCollection {
        let expired = fetchedAt.map { isCacheExpired($0) } ?? true
        if !forceRefresh && !expired {
            return keyCollection
        }
        return try await refresh()
    }

    private func refresh() async throws -> JWTKeyCollection {
        if let existing = fetchTask {
            return try await existing.value
        }
        // Task {} inherits this actor's isolation, so the `defer` writes to `fetchTask`
        // on-actor. Do not change to Task.detached or @concurrent.
        let task = Task<JWTKeyCollection, Error> {
            defer { self.fetchTask = nil }
            return try await self.fetch()
        }
        fetchTask = task
        return try await task.value
    }

    private func fetch() async throws -> JWTKeyCollection {
        logger.debug("Fetching JWKS", metadata: ["url": "\(jwksURL)"])
        var request = HTTPClientRequest(url: jwksURL)
        request.method = .GET
        request.headers.add(name: "Accept", value: "application/json")

        let response = try await httpClient.execute(request, timeout: .seconds(10))
        guard response.status == .ok else {
            throw OIDCError.jwksFetchFailed(reason: "HTTP \(Int(response.status.code))")
        }
        let body = try await response.body.collect(upTo: 1024 * 256)
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(buffer: body))

        let collection = JWTKeyCollection()
        for (index, key) in jwks.keys.enumerated() {
            // JWTKit's add(jwk:) requires a key identifier.  For kid-less keys we
            // assign a synthetic one so the key is stored and becomes the default
            // signer — JWTKit falls back to the default when a JWT carries no kid.
            var loadableKey = key
            if loadableKey.keyIdentifier == nil {
                loadableKey.keyIdentifier = JWKIdentifier(string: "__kidless_\(index)")
            }
            try await collection.add(jwk: loadableKey)
        }
        self.keyCollection = collection
        self.fetchedAt = Date()
        logger.debug("JWKS loaded", metadata: ["keyCount": "\(jwks.keys.count)"])
        return collection
    }

    private func isCacheExpired(_ date: Date) -> Bool {
        Date().timeIntervalSince(date) >= cacheTTL.timeInterval
    }
}
