//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Hummingbird

/// Transient data persisted between the /login redirect and the /callback.
public struct OIDCAuthRequestState: Codable, Sendable {
    /// The `state` parameter sent to the IdP (used for CSRF validation)
    public let state: String
    /// The `nonce` claim sent in the authorization request
    public let nonce: String
    /// PKCE code verifier, sent to the token endpoint
    public let pkceVerifier: String
    /// The validated relative path the user was trying to reach before being redirected
    /// to login. After a successful callback the user is redirected here instead of the
    /// static `postLoginRedirectPath`. Nil means fall back to the static path.
    public let returnTo: String?

    public init(
        state: String,
        nonce: String,
        pkceVerifier: String,
        returnTo: String? = nil
    ) {
        self.state = state
        self.nonce = nonce
        self.pkceVerifier = pkceVerifier
        self.returnTo = returnTo
    }
}

/// Storage for auth-request state (state/nonce/PKCE) between /login and /callback.
///
/// Implementations must provide **consume** semantics: reading an entry deletes it
/// so that a replayed callback cannot reuse the same state value.
///
/// True atomicity requires backend-specific support (e.g. Redis `GETDEL`). The default
/// `PersistDriverStateStore` is best-effort only — see its `consume` documentation.
/// Use `InMemoryStateStore` for single-node deployments where true atomicity is required.
public protocol OIDCStateStore: Sendable {
    /// Persist a new auth-request state entry.
    func save(_ entry: OIDCAuthRequestState, expiresIn: Duration) async throws
    /// Atomically read-and-delete the entry for the given state value.
    /// Returns nil if the state does not exist or has expired.
    func consume(state: String) async throws -> OIDCAuthRequestState?
}

/// Default implementation that uses Hummingbird's `PersistDriver` (same storage
/// used by `SessionMiddleware`).
///
/// > Warning: `consume` is **not truly atomic**. The get and remove are two separate
/// > async calls with a race window between them. A replayed callback arriving
/// > concurrently could read the same state entry before the remove completes, defeating
/// > the one-time-use guarantee. For strict atomicity use a backend that supports atomic
/// > read-and-delete (e.g. Redis `GETDEL`) or use `InMemoryStateStore` on a single node.
public struct PersistDriverStateStore: OIDCStateStore {
    let storage: any PersistDriver
    let keyPrefix: String

    public init(_ storage: any PersistDriver, keyPrefix: String = "oidc.state.") {
        self.storage = storage
        self.keyPrefix = keyPrefix
    }

    public func save(_ entry: OIDCAuthRequestState, expiresIn: Duration) async throws {
        try await storage.set(key: "\(keyPrefix)\(entry.state)", value: entry, expires: expiresIn)
    }

    public func consume(state: String) async throws -> OIDCAuthRequestState? {
        let key = "\(keyPrefix)\(state)"
        // WARNING: not truly atomic — see type-level documentation.
        guard let entry = try await storage.get(key: key, as: OIDCAuthRequestState.self) else {
            return nil
        }
        try await storage.remove(key: key)
        return entry
    }
}

/// Actor-based in-memory state store that performs get+delete inside a single
/// actor-isolated call, providing true atomicity.
///
/// Suitable for single-node deployments and testing. Does not survive process restarts.
public actor InMemoryStateStore: OIDCStateStore {
    private var entries: [String: (entry: OIDCAuthRequestState, expiresAt: ContinuousClock.Instant)] = [:]

    public init() {}

    public func save(_ entry: OIDCAuthRequestState, expiresIn: Duration) async throws {
        entries[entry.state] = (entry, ContinuousClock.now + expiresIn)
    }

    public func consume(state: String) async throws -> OIDCAuthRequestState? {
        guard let record = entries[state] else { return nil }
        entries.removeValue(forKey: state)
        guard ContinuousClock.now < record.expiresAt else { return nil }
        return record.entry
    }
}
