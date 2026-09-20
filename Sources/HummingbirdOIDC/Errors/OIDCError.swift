//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

/// Errors produced by the HummingbirdOIDC module.
public struct OIDCError: Error, Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case discoveryFailed(reason: String)
        case invalidProviderMetadata(reason: String)
        case jwksFetchFailed(reason: String)
        case invalidState
        case stateExpired
        case idTokenInvalid(reason: IDTokenInvalidReason)
        case tokenExchangeFailed(statusCode: Int, body: String)
        case userInfoFailed(reason: String)
        case providerError(code: String, description: String?)
        case missingClientSecret
        case configurationError(reason: String)
    }

    public enum IDTokenInvalidReason: Equatable, Sendable {
        case signatureVerificationFailed
        case expired
        case notYetValid
        case issuerMismatch
        case audienceMismatch
        case nonceMismatch
        case missingNonce
        case accessTokenHashMismatch
        case unsupportedAlgorithm(String)
        case other(String)
    }

    let kind: Kind

    private init(_ kind: Kind) { self.kind = kind }

    public static func discoveryFailed(reason: String) -> Self { .init(.discoveryFailed(reason: reason)) }
    public static func invalidProviderMetadata(reason: String) -> Self { .init(.invalidProviderMetadata(reason: reason)) }
    public static func jwksFetchFailed(reason: String) -> Self { .init(.jwksFetchFailed(reason: reason)) }
    public static var invalidState: Self { .init(.invalidState) }
    public static var stateExpired: Self { .init(.stateExpired) }
    public static func idTokenInvalid(_ reason: IDTokenInvalidReason) -> Self { .init(.idTokenInvalid(reason: reason)) }
    public static func tokenExchangeFailed(statusCode: Int, body: String) -> Self { .init(.tokenExchangeFailed(statusCode: statusCode, body: body)) }
    public static func userInfoFailed(reason: String) -> Self { .init(.userInfoFailed(reason: reason)) }
    public static func providerError(code: String, description: String?) -> Self { .init(.providerError(code: code, description: description)) }
    public static var missingClientSecret: Self { .init(.missingClientSecret) }
    public static func configurationError(reason: String) -> Self { .init(.configurationError(reason: reason)) }
}
