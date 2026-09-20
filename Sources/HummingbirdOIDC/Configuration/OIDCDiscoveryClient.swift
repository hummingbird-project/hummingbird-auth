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
import Logging
import NIOCore
import NIOFoundationCompat

/// Fetches and caches the OIDC provider discovery document.
public actor OIDCDiscoveryClient {
    private var cached: OIDCProviderMetadata?
    private var fetchedAt: Date?
    private var fetchTask: Task<OIDCProviderMetadata, Error>?
    private let cacheTTL: Duration
    private let httpClient: HTTPClient
    private let issuer: String
    private let logger: Logger

    /// - Parameter issuer: The issuer identifier exactly as published by the provider.
    ///   Must NOT have a trailing slash (OIDC Discovery 1.0 §4.1 appends
    ///   `/.well-known/openid-configuration` literally).
    public init(issuer: String, cacheTTL: Duration, httpClient: HTTPClient, logger: Logger = Logger(label: "hummingbird-oidc.discovery")) {
        self.issuer = issuer
        self.cacheTTL = cacheTTL
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Returns a cached or freshly fetched metadata document.
    ///
    /// Concurrent callers that arrive with a cold or expired cache share a single in-flight
    /// fetch via `fetchTask`, so only one HTTP request is made to the discovery endpoint.
    public func metadata() async throws -> OIDCProviderMetadata {
        if let cached, let fetchedAt, !isCacheExpired(fetchedAt) {
            return cached
        }
        if let existing = fetchTask {
            return try await existing.value
        }
        // Task {} inherits this actor's isolation, so the `defer` writes to `fetchTask`
        // on-actor. Do not change to Task.detached or @concurrent.
        let task = Task<OIDCProviderMetadata, Error> {
            defer { self.fetchTask = nil }
            return try await self.fetch()
        }
        fetchTask = task
        return try await task.value
    }

    private func fetch() async throws -> OIDCProviderMetadata {
        let discoveryURL = "\(issuer)/.well-known/openid-configuration"
        logger.debug("Fetching OIDC discovery document", metadata: ["url": "\(discoveryURL)"])

        var request = HTTPClientRequest(url: discoveryURL)
        request.method = .GET
        request.headers.add(name: "Accept", value: "application/json")

        let response = try await httpClient.execute(request, timeout: .seconds(10))
        guard response.status == .ok else {
            throw OIDCError.discoveryFailed(reason: "HTTP \(Int(response.status.code))")
        }
        let body = try await response.body.collect(upTo: 1024 * 256)
        let metadata = try JSONDecoder().decode(OIDCProviderMetadata.self, from: Data(buffer: body))

        guard metadata.issuer == issuer else {
            throw OIDCError.invalidProviderMetadata(reason: "issuer mismatch: got \(metadata.issuer), expected \(issuer)")
        }

        self.cached = metadata
        self.fetchedAt = Date()
        return metadata
    }

    private func isCacheExpired(_ fetchedAt: Date) -> Bool {
        Date().timeIntervalSince(fetchedAt) >= cacheTTL.timeInterval
    }
}
