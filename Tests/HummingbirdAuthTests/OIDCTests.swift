//
// This source file is part of the Hummingbird server framework project
// Copyright (c) the Hummingbird authors
//
// See LICENSE.txt for license information
// SPDX-License-Identifier: Apache-2.0
//

import AsyncHTTPClient
import Crypto
import Foundation
import HTTPTypes
import Hummingbird
import HummingbirdAuth
import Logging
@testable import HummingbirdOIDC
import HummingbirdTesting
import JWTKit
import Testing

// MARK: - PKCE tests

struct PKCETests {
    @Test func generatesUniqueVerifiers() {
        let a = PKCE()
        let b = PKCE()
        #expect(a.verifier != b.verifier)
        #expect(a.challenge != b.challenge)
    }

    @Test func challengeMethodIsS256() {
        #expect(PKCE().challengeMethod == "S256")
    }

    /// RFC 7636 Appendix B known-answer vector
    @Test func knownAnswerVector() {
        // verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        // challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        // These are the exact bytes from RFC 7636 Appendix B.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let digest = SHA256.hash(data: Data(verifier.utf8))
        // RFC challenge is the full hash base64url-encoded (not half)
        let challenge = PKCE.base64URLEncode(Array(digest))
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        #expect(challenge == expected)
    }

    @Test func verifierIsURLSafe() {
        let pkce = PKCE()
        #expect(!pkce.verifier.contains("+"))
        #expect(!pkce.verifier.contains("/"))
        #expect(!pkce.verifier.contains("="))
        #expect(!pkce.challenge.contains("+"))
        #expect(!pkce.challenge.contains("/"))
        #expect(!pkce.challenge.contains("="))
    }

    // 32 random bytes → base64url → 43 chars (no padding). SHA-256 also produces 32 bytes.
    @Test func verifierAndChallengeHaveExpectedLength() {
        let pkce = PKCE()
        #expect(pkce.verifier.count == 43)
        #expect(pkce.challenge.count == 43)
    }
}

// MARK: - TokenExchange urlEncode tests

struct URLEncodeTests {
    private func makeEncoder() -> TokenExchange {
        let config = OIDCConfiguration(
            clientID: "c",
            redirectURI: "https://example.com/cb",
            issuer: "https://example.com",
            tokenEndpointAuthMethod: .none
        )
        return TokenExchange(
            configuration: config,
            httpClient: .shared,
            logger: Logger(label: "test")
        )
    }

    @Test func encodesAmpersand() {
        #expect(makeEncoder().urlEncode("a&b") == "a%26b")
    }

    @Test func encodesEquals() {
        #expect(makeEncoder().urlEncode("a=b") == "a%3Db")
    }

    @Test func encodesPlus() {
        #expect(makeEncoder().urlEncode("a+b") == "a%2Bb")
    }

    @Test func encodesSlash() {
        #expect(makeEncoder().urlEncode("a/b") == "a%2Fb")
    }

    @Test func encodesMultibyteUTF8() {
        // "é" is 0xC3 0xA9 in UTF-8 — both bytes must be percent-encoded
        #expect(makeEncoder().urlEncode("caf\u{00e9}") == "caf%C3%A9")
    }

    @Test func preservesUnreservedCharacters() {
        let unreserved = "abcXYZ0-._~"
        #expect(makeEncoder().urlEncode(unreserved) == unreserved)
    }
}

// MARK: - OIDCError tests

struct OIDCErrorTests {
    @Test func equalityByKind() {
        #expect(OIDCError.invalidState == OIDCError.invalidState)
        #expect(OIDCError.stateExpired == OIDCError.stateExpired)
        #expect(OIDCError.invalidState != OIDCError.stateExpired)
        #expect(
            OIDCError.idTokenInvalid(.expired) == OIDCError.idTokenInvalid(.expired)
        )
        #expect(
            OIDCError.idTokenInvalid(.expired) != OIDCError.idTokenInvalid(.issuerMismatch)
        )
    }
}

// MARK: - State store tests

struct StateStoreTests {
    @Test func saveAndConsume() async throws {
        let persist = MemoryPersistDriver()
        let store = PersistDriverStateStore(persist)
        let entry = OIDCAuthRequestState(
            state: "abc123",
            nonce: "nonce1",
            pkceVerifier: "verifier1"
        )
        try await store.save(entry, expiresIn: .seconds(300))
        let retrieved = try await store.consume(state: "abc123")
        #expect(retrieved?.nonce == "nonce1")
        #expect(retrieved?.pkceVerifier == "verifier1")

        // Second consume returns nil (single-use)
        let second = try await store.consume(state: "abc123")
        #expect(second == nil)
    }

    @Test func consumeMissingStateReturnsNil() async throws {
        let persist = MemoryPersistDriver()
        let store = PersistDriverStateStore(persist)
        let result = try await store.consume(state: "does-not-exist")
        #expect(result == nil)
    }
}

// MARK: - InMemoryStateStore tests

struct InMemoryStateStoreTests {
    @Test func saveAndConsume() async throws {
        let store = InMemoryStateStore()
        let entry = OIDCAuthRequestState(state: "s1", nonce: "n1", pkceVerifier: "v1")
        try await store.save(entry, expiresIn: .seconds(300))
        let retrieved = try await store.consume(state: "s1")
        #expect(retrieved?.nonce == "n1")
        let second = try await store.consume(state: "s1")
        #expect(second == nil)
    }

    @Test func consumeMissingReturnsNil() async throws {
        let store = InMemoryStateStore()
        let result = try await store.consume(state: "missing")
        #expect(result == nil)
    }

    @Test func consumeExpiredEntryReturnsNil() async throws {
        let store = InMemoryStateStore()
        let entry = OIDCAuthRequestState(state: "exp1", nonce: "n", pkceVerifier: "v")
        try await store.save(entry, expiresIn: .milliseconds(1))
        try await Task.sleep(for: .milliseconds(10))
        let result = try await store.consume(state: "exp1")
        #expect(result == nil)
    }
}

// MARK: - Provider metadata tests

struct ProviderMetadataTests {
    @Test func decodesDiscoveryDocument() throws {
        let json = """
        {
            "issuer": "https://accounts.example.com",
            "authorization_endpoint": "https://accounts.example.com/o/oauth2/auth",
            "token_endpoint": "https://oauth2.example.com/token",
            "jwks_uri": "https://www.example.com/oauth2/certs",
            "userinfo_endpoint": "https://openidconnect.example.com/v1/userinfo",
            "end_session_endpoint": "https://accounts.example.com/logout",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """
        let metadata = try JSONDecoder().decode(OIDCProviderMetadata.self, from: Data(json.utf8))
        #expect(metadata.issuer == "https://accounts.example.com")
        #expect(metadata.tokenEndpoint == "https://oauth2.example.com/token")
        #expect(metadata.jwksURI == "https://www.example.com/oauth2/certs")
        #expect(metadata.userInfoEndpoint == "https://openidconnect.example.com/v1/userinfo")
        #expect(metadata.endSessionEndpoint == "https://accounts.example.com/logout")
        #expect(metadata.idTokenSigningAlgValuesSupported == ["RS256"])
    }

    @Test func decodesMinimalDiscoveryDocument() throws {
        let json = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """
        let metadata = try JSONDecoder().decode(OIDCProviderMetadata.self, from: Data(json.utf8))
        #expect(metadata.userInfoEndpoint == nil)
        #expect(metadata.endSessionEndpoint == nil)
        #expect(metadata.subjectTypesSupported == ["public"])
    }

    /// Issue 7 (P1): OIDC Discovery 1.0 §3 makes subject_types_supported REQUIRED.
    /// Decoding a discovery document without it must fail.
    @Test func decodingRejectsDocumentMissingSubjectTypesSupported() throws {
        let json = """
        {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }
        """
        #expect(throws: (any Error).self) {
            _ = try JSONDecoder().decode(OIDCProviderMetadata.self, from: Data(json.utf8))
        }
    }
}

// MARK: - JWT / ID token verification tests

struct IDTokenVerificationTests {
    /// Build a minimal signed ID token using JWTKit (ES256).
    private func makeToken(
        issuer: String = "https://idp.example.com",
        audience: String = "my-client",
        subject: String = "user-123",
        nonce: String? = "test-nonce",
        expiresIn: TimeInterval = 3600,
        keys: JWTKeyCollection,
        kid: JWKIdentifier
    ) async throws -> String {
        struct TestPayload: JWTPayload {
            var iss: IssuerClaim
            var sub: SubjectClaim
            var aud: AudienceClaim
            var exp: ExpirationClaim
            var iat: IssuedAtClaim
            var nonce: String?
            func verify(using algorithm: some JWTAlgorithm) async throws {
                try exp.verifyNotExpired()
            }
        }
        let payload = TestPayload(
            iss: .init(value: issuer),
            sub: .init(value: subject),
            aud: .init(value: [audience]),
            exp: .init(value: Date().addingTimeInterval(expiresIn)),
            iat: .init(value: Date()),
            nonce: nonce
        )
        return try await keys.sign(payload, kid: kid)
    }

    @Test func verifyValidToken() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(keys: keyCollection, kid: kid)

        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)
        try payload.verify(
            expectedIssuer: "https://idp.example.com",
            clientID: "my-client",
            expectedNonce: "test-nonce",
            clockSkew: .seconds(60)
        )
        #expect(payload.subject.value == "user-123")
    }

    /// A deeply expired token (1h ago) passes JWTKit signature verification (exp is no longer
    /// checked there) but must be rejected by our skew-aware verify step.
    @Test func rejectsExpiredToken() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(expiresIn: -3600, keys: keyCollection, kid: kid)

        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)
        #expect(throws: OIDCError.idTokenInvalid(.expired)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    @Test func rejectsWrongIssuer() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(issuer: "https://evil.example.com", keys: keyCollection, kid: kid)
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.issuerMismatch)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    @Test func rejectsWrongAudience() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(audience: "other-client", keys: keyCollection, kid: kid)
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.audienceMismatch)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    @Test func rejectsWrongNonce() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(nonce: "correct-nonce", keys: keyCollection, kid: kid)
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.nonceMismatch)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: "wrong-nonce",
                clockSkew: .seconds(60)
            )
        }
    }

    @Test func atHashVerificationPassesWhenMatching() throws {
        let accessToken = "some-access-token"
        let digest = SHA256.hash(data: Data(accessToken.utf8))
        let firstHalf = Array(digest.prefix(SHA256.byteCount / 2))
        let atHash = PKCE.base64URLEncode(firstHalf)

        var payload = OIDCIDTokenPayload(
            issuer: IssuerClaim(value: "https://idp.example.com"),
            subject: SubjectClaim(value: "u1"),
            audience: AudienceClaim(value: ["client"]),
            expiration: ExpirationClaim(value: Date().addingTimeInterval(3600)),
            issuedAt: IssuedAtClaim(value: Date())
        )
        payload.atHash = atHash
        // Should not throw
        try payload.verifyAccessTokenHash(accessToken)
    }

    // MARK: Fix 5 — JWKS cache must be reused across resolveVerifier calls

    /// Regression test: in `.discovered` mode, `resolveVerifier(metadata:)` must return
    /// a verifier backed by the **same** `JWKSCache` actor on every call.
    ///
    /// Before the fix, a fresh `JWKSCache` was created each invocation so the cache
    /// was discarded after every request, causing every authenticated request to
    /// re-fetch JWKS from the provider.
    @Test func resolveVerifierReusesCacheAcrossCalls() {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/.well-known/jwks.json"
        )

        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .discovered
        )
        let persist = MemoryPersistDriver()
        let stateStore = PersistDriverStateStore(persist)
        let oidc = OIDC(configuration: config, stateStore: stateStore)

        let verifier1 = oidc.resolveVerifier(metadata: metadata)
        let verifier2 = oidc.resolveVerifier(metadata: metadata)

        // Both calls must return a verifier backed by the identical JWKSCache actor.
        // If the cache is not shared, ObjectIdentifier will differ and the test fails.
        #expect(
            ObjectIdentifier(verifier1.jwksCache) == ObjectIdentifier(verifier2.jwksCache),
            "resolveVerifier must reuse the same JWKSCache across calls in .discovered mode"
        )
    }

    // MARK: Fix 1 — sub must be non-empty

    /// OIDC Core §2: sub must be a non-empty string.
    @Test func rejectsEmptySubject() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(subject: "", keys: keyCollection, kid: kid)
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.other("subject missing"))) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    // MARK: Fix 2 — iat must not be in the future

    /// OIDC Core §3.1.3.7 step 9: iat must not be in the future (within clock skew).
    @Test func rejectsFutureIssuedAt() async throws {
        struct TestPayloadWithFutureIat: JWTPayload {
            var iss: IssuerClaim
            var sub: SubjectClaim
            var aud: AudienceClaim
            var exp: ExpirationClaim
            var iat: IssuedAtClaim
            var nonce: String?
            func verify(using algorithm: some JWTAlgorithm) async throws {}
        }
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let futureIat = Date().addingTimeInterval(10 * 60)  // 10 minutes in future
        let payload = TestPayloadWithFutureIat(
            iss: .init(value: "https://idp.example.com"),
            sub: .init(value: "user-123"),
            aud: .init(value: ["my-client"]),
            exp: .init(value: Date().addingTimeInterval(3600)),
            iat: .init(value: futureIat),
            nonce: nil
        )
        let token = try await keyCollection.sign(payload, kid: kid)
        let verified = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.other("iat in future"))) {
            try verified.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    // MARK: Fix 3 — relaxed azp check

    /// Helper for multi-audience tokens.
    private func makeMultiAudienceToken(
        audiences: [String],
        azp: String?,
        keys: JWTKeyCollection,
        kid: JWKIdentifier
    ) async throws -> String {
        struct TestPayloadMultiAud: JWTPayload {
            var iss: IssuerClaim
            var sub: SubjectClaim
            var aud: AudienceClaim
            var exp: ExpirationClaim
            var iat: IssuedAtClaim
            var azp: String?
            func verify(using algorithm: some JWTAlgorithm) async throws {}
        }
        let payload = TestPayloadMultiAud(
            iss: .init(value: "https://idp.example.com"),
            sub: .init(value: "user-123"),
            aud: .init(value: audiences),
            exp: .init(value: Date().addingTimeInterval(3600)),
            iat: .init(value: Date()),
            azp: azp
        )
        return try await keys.sign(payload, kid: kid)
    }

    /// Multi-audience token with azp == clientID must pass.
    @Test func multiAudienceWithMatchingAzpPasses() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeMultiAudienceToken(
            audiences: ["my-client", "other-service"],
            azp: "my-client",
            keys: keyCollection,
            kid: kid
        )
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)
        // Should not throw
        try payload.verify(
            expectedIssuer: "https://idp.example.com",
            clientID: "my-client",
            expectedNonce: nil,
            clockSkew: .seconds(60)
        )
    }

    /// Issue 5 (P1): multi-audience token with azp absent must be rejected.
    /// Enforcing azp for multi-aud prevents audience-confusion attacks even
    /// though OIDC Core §3.1.3.7 step 4 says SHOULD rather than MUST.
    @Test func multiAudienceWithoutAzpFails() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeMultiAudienceToken(
            audiences: ["my-client", "other-service"],
            azp: nil,
            keys: keyCollection,
            kid: kid
        )
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)
        #expect(throws: OIDCError.idTokenInvalid(.audienceMismatch)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    /// Single-audience token with azp present but wrong must fail.
    @Test func singleAudienceWithWrongAzpFails() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeMultiAudienceToken(
            audiences: ["my-client"],
            azp: "evil-client",
            keys: keyCollection,
            kid: kid
        )
        let payload = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.audienceMismatch)) {
            try payload.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    // MARK: Issue 1 — alg restriction (P0)

    /// P0 alg-confusion guard: a token whose JOSE header `alg` is not in the
    /// verifier's allowed list must be rejected before JWKS is even fetched.
    @Test func rejectsTokenWithDisallowedAlgorithm() async throws {
        // Token signed with ES256; verifier configured for RS256 only.
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "alg-test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)
        let token = try await makeToken(keys: keyCollection, kid: kid)

        // The JWKS URL is unreachable — alg check must fire before any fetch.
        let cache = JWKSCache(
            jwksURL: "http://localhost:1/unreachable",
            cacheTTL: .seconds(60),
            httpClient: .shared
        )
        let verifier = JWTVerifier(jwksCache: cache, allowedAlgorithms: ["RS256"])

        await #expect(throws: OIDCError.idTokenInvalid(.unsupportedAlgorithm("ES256"))) {
            _ = try await verifier.verify(
                idToken: token,
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(60)
            )
        }
    }

    // MARK: Issue 10 (P2) — maxIDTokenAge freshness window

    /// A token whose iat is older than maxIDTokenAge (outside clock skew) must be rejected.
    @Test func rejectsTokenOlderThanMaxAge() async throws {
        struct OldTokenPayload: JWTPayload {
            var iss: IssuerClaim; var sub: SubjectClaim; var aud: AudienceClaim
            var exp: ExpirationClaim; var iat: IssuedAtClaim
            func verify(using algorithm: some JWTAlgorithm) async throws {}
        }
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "age-test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        // iat = 90 seconds ago, maxIDTokenAge = 60 seconds → stale
        let staleIat = Date().addingTimeInterval(-90)
        let payload = OldTokenPayload(
            iss: .init(value: "https://idp.example.com"),
            sub: .init(value: "user-123"),
            aud: .init(value: ["my-client"]),
            exp: .init(value: Date().addingTimeInterval(3600)),
            iat: .init(value: staleIat)
        )
        let token = try await keyCollection.sign(payload, kid: kid)
        let verified = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        #expect(throws: OIDCError.idTokenInvalid(.other("id_token too old"))) {
            try verified.verify(
                expectedIssuer: "https://idp.example.com",
                clientID: "my-client",
                expectedNonce: nil,
                clockSkew: .seconds(10),
                maxIDTokenAge: .seconds(60)
            )
        }
    }

    /// A fresh token within maxIDTokenAge must still pass.
    @Test func acceptsTokenWithinMaxAge() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "age-test-key-2")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await makeToken(keys: keyCollection, kid: kid)
        let verified = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)

        // iat ≈ now, maxIDTokenAge = 60 s → must pass
        try verified.verify(
            expectedIssuer: "https://idp.example.com",
            clientID: "my-client",
            expectedNonce: "test-nonce",
            clockSkew: .seconds(10),
            maxIDTokenAge: .seconds(60)
        )
    }

    // MARK: Fix 4 — token within clock-skew window must pass

    /// Fix 4: token expired 30s ago, clockSkew 60s → should pass.
    /// Currently fails because verify(using:) calls verifyNotExpired() without skew.
    @Test func acceptsTokenWithinClockSkewWindow() async throws {
        struct TestPayloadSkew: JWTPayload {
            var iss: IssuerClaim
            var sub: SubjectClaim
            var aud: AudienceClaim
            var exp: ExpirationClaim
            var iat: IssuedAtClaim
            func verify(using algorithm: some JWTAlgorithm) async throws {}
        }
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let expiredBy30s = Date().addingTimeInterval(-30)
        let payload = TestPayloadSkew(
            iss: .init(value: "https://idp.example.com"),
            sub: .init(value: "user-123"),
            aud: .init(value: ["my-client"]),
            exp: .init(value: expiredBy30s),
            iat: .init(value: Date().addingTimeInterval(-60))
        )
        let token = try await keyCollection.sign(payload, kid: kid)
        let verified = try await keyCollection.verify(token, as: OIDCIDTokenPayload.self)
        // Should not throw: 30s past exp is within 60s skew
        try verified.verify(
            expectedIssuer: "https://idp.example.com",
            clientID: "my-client",
            expectedNonce: nil,
            clockSkew: .seconds(60)
        )
    }
}

// MARK: - JWKSCache tests

/// Tests for `JWKSCache` — specifically the bug where kid-less JWK entries were
/// silently dropped, making Apple- and Cognito-style tokens unverifiable.
struct JWKSCacheTests {
    // Minimal JWTPayload used only for sign/verify round-trips in this suite.
    private struct MinimalPayload: JWTPayload {
        var sub: SubjectClaim
        var exp: ExpirationClaim
        var iat: IssuedAtClaim
        func verify(using _: some JWTAlgorithm) async throws {
            try exp.verifyNotExpired()
        }
    }

    /// Regression test: a JWKS containing an EC key with **no `kid`** must be loaded
    /// into the key collection and used to verify a JWT that also carries no `kid`.
    ///
    /// Providers such as Apple Sign-In and certain Cognito configurations publish
    /// kid-less JWKs.  Before the fix, `JWKSCache.fetch()` filtered them out with
    /// `where key.keyIdentifier != nil`, leaving the collection empty and making
    /// every such token unverifiable.
    @Test func loadsKidlessJWKAndVerifiesToken() async throws {
        // 1. Generate a fresh ES256 key pair.
        let privateKey = ES256PrivateKey()

        // 2. Extract the public key x/y coordinates for the JWKS JSON.
        //    `parameters` returns base64-encoded (standard alphabet) strings;
        //    JWTKit's decoder accepts both standard and URL-safe base64 in JWK.
        guard let params = privateKey.parameters else {
            Issue.record("Could not extract EC parameters from generated key")
            return
        }

        // 3. Build JWKS JSON — intentionally omit "kid".
        let jwksJSON = """
            {
                "keys": [
                    {
                        "kty": "EC",
                        "use": "sig",
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": "\(params.x)",
                        "y": "\(params.y)"
                    }
                ]
            }
            """

        // 4. Stand up a tiny live server that returns the JWKS JSON.
        //    Port 0 lets the OS pick a free port; we use localhost per repo convention.
        let router = Router()
        router.get("/.well-known/jwks.json") { _, _ -> Response in
            var headers = HTTPFields()
            headers[.contentType] = "application/json"
            return Response(
                status: .ok,
                headers: headers,
                body: .init(byteBuffer: ByteBuffer(string: jwksJSON))
            )
        }
        let app = Application(responder: router.buildResponder())

        try await app.test(.live) { client in
            let port = try #require(client.port, "Test server must expose a port")
            let jwksURL = "http://localhost:\(port)/.well-known/jwks.json"

            // 5. Create a JWKSCache pointing at the test server.
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let cache = JWKSCache(
                jwksURL: jwksURL,
                cacheTTL: .seconds(60),
                httpClient: httpClient
            )

            // 6. Sign a JWT using the private key with NO kid header.
            //    The signing collection has no kid so the JWT header gets no kid either.
            let signingKeys = JWTKeyCollection()
            await signingKeys.add(ecdsa: privateKey)  // no kid → becomes default
            let token = try await signingKeys.sign(
                MinimalPayload(
                    sub: .init(value: "u1"),
                    exp: .init(value: Date().addingTimeInterval(3600)),
                    iat: .init(value: Date())
                )
            )

            // 7. Fetch the key collection from the cache and verify the token.
            //    Before the fix this throws because the kid-less key is discarded.
            let keyCollection = try await cache.keyCollection()
            let payload = try await keyCollection.verify(token, as: MinimalPayload.self)
            #expect(payload.sub.value == "u1")
        }
    }
}

// MARK: - ReturnTo tests

struct ReturnToTests {

    // MARK: Helpers

    private func makeOIDC(postLoginRedirectPath: String = "/") -> OIDC {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/.well-known/jwks.json"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata),
            postLoginRedirectPath: postLoginRedirectPath
        )
        let persist = MemoryPersistDriver()
        let stateStore = PersistDriverStateStore(persist)
        return OIDC(configuration: config, stateStore: stateStore)
    }

    /// Call handleLogin with a URI containing ?returnTo=<path> and return the stored state.
    private func loginAndCaptureState(oidc: OIDC, uri: String) async throws -> OIDCAuthRequestState? {
        // We need to intercept what was stored. Build a spy state store.
        let spy = SpyStateStore()
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/.well-known/jwks.json"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidcWithSpy = OIDC(configuration: config, stateStore: spy)

        let httpRequest = HTTPRequest(method: .get, scheme: "https", authority: "app.example.com", path: uri)
        let request = Request(head: httpRequest, body: .init(buffer: ByteBuffer()))
        _ = try await oidcWithSpy.handleLogin(request: request)
        return spy.lastSaved
    }

    // MARK: Validator tests (via handleLogin + SpyStateStore)

    @Test func validReturnToPathIsStored() async throws {
        let state = try await loginAndCaptureState(oidc: makeOIDC(), uri: "/login?returnTo=/dashboard")
        #expect(state?.returnTo == "/dashboard")
    }

    @Test func validReturnToWithQueryAndFragment() async throws {
        let state = try await loginAndCaptureState(oidc: makeOIDC(), uri: "/login?returnTo=/path%3Fquery%3D1")
        // The URI query parameter value is URL-encoded; the stored value should be the decoded path.
        // returnTo=/path?query=1
        #expect(state?.returnTo == "/path?query=1")
    }

    @Test func returnToWithSlashAndSubpath() async throws {
        let state = try await loginAndCaptureState(oidc: makeOIDC(), uri: "/login?returnTo=/users/42")
        #expect(state?.returnTo == "/users/42")
    }

    @Test func invalidReturnToAbsoluteURLIsIgnored() async throws {
        let state = try await loginAndCaptureState(
            oidc: makeOIDC(), uri: "/login?returnTo=https://attacker.com/")
        #expect(state?.returnTo == nil)
    }

    @Test func invalidReturnToProtocolRelativeIsIgnored() async throws {
        let state = try await loginAndCaptureState(
            oidc: makeOIDC(), uri: "/login?returnTo=//attacker.com/foo")
        #expect(state?.returnTo == nil)
    }

    @Test func invalidReturnToBackslashIsIgnored() async throws {
        let state = try await loginAndCaptureState(
            oidc: makeOIDC(), uri: "/login?returnTo=/\\evil.com")
        #expect(state?.returnTo == nil)
    }

    @Test func invalidReturnToJavascriptSchemeIsIgnored() async throws {
        let state = try await loginAndCaptureState(
            oidc: makeOIDC(), uri: "/login?returnTo=javascript:alert(1)")
        #expect(state?.returnTo == nil)
    }

    @Test func invalidReturnToWithSpacesIsIgnored() async throws {
        let state = try await loginAndCaptureState(
            oidc: makeOIDC(), uri: "/login?returnTo=/foo%20bar")
        // Decoded value "/foo bar" contains whitespace → should be rejected.
        #expect(state?.returnTo == nil)
    }

    @Test func invalidReturnToEmptyStringIsIgnored() async throws {
        let state = try await loginAndCaptureState(oidc: makeOIDC(), uri: "/login?returnTo=")
        #expect(state?.returnTo == nil)
    }

    @Test func missingReturnToParamStoresNil() async throws {
        let state = try await loginAndCaptureState(oidc: makeOIDC(), uri: "/login")
        #expect(state?.returnTo == nil)
    }

    // MARK: Legacy decode compatibility

    /// A state record serialised without `returnTo` (legacy format) must still decode,
    /// with `returnTo == nil`.
    @Test func legacyStateDecodesWithNilReturnTo() throws {
        let json = """
        {
            "state": "abc",
            "nonce": "xyz",
            "pkceVerifier": "verifier123",
            "createdAt": 0
        }
        """
        let decoded = try JSONDecoder().decode(OIDCAuthRequestState.self, from: Data(json.utf8))
        #expect(decoded.returnTo == nil)
        #expect(decoded.state == "abc")
        #expect(decoded.nonce == "xyz")
    }

    // MARK: callbackSessionHandler uses returnTo when present

    /// When the stored state contains a `returnTo`, callbackSessionHandler must redirect
    /// there instead of `configuration.postLoginRedirectPath`.
    @Test func callbackRedirectsToReturnToWhenPresent() async throws {
        // Stand up a fake token endpoint + JWKS endpoint so processCallback can run.
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-1")
        let privateKey = ES256PrivateKey()
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        // Build a real ID token.
        struct TestPayload: JWTPayload {
            var iss: IssuerClaim
            var sub: SubjectClaim
            var aud: AudienceClaim
            var exp: ExpirationClaim
            var iat: IssuedAtClaim
            var nonce: String?
            func verify(using _: some JWTAlgorithm) async throws {}
        }

        guard let params = privateKey.parameters else {
            Issue.record("Could not extract EC key parameters")
            return
        }

        let nonce = "test-nonce"
        let stateValue = "test-state"
        let idToken = try await keyCollection.sign(
            TestPayload(
                iss: .init(value: "https://idp.example.com"),
                sub: .init(value: "user-123"),
                aud: .init(value: ["test-client"]),
                exp: .init(value: Date().addingTimeInterval(3600)),
                iat: .init(value: Date()),
                nonce: nonce
            ),
            kid: kid
        )

        let jwksJSON = """
        {
            "keys": [{
                "kty": "EC",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "kid": "test-key-1",
                "x": "\(params.x)",
                "y": "\(params.y)"
            }]
        }
        """
        let tokenResponseJSON = """
        {"access_token":"access-tok","token_type":"Bearer","id_token":"\(idToken)"}
        """

        // Router serving the fake IdP endpoints.
        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields()
            h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields()
            h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let baseURL = "http://localhost:\(port)"

            let liveMetadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "\(baseURL)/auth",
                tokenEndpoint: "\(baseURL)/token",
                jwksURI: "\(baseURL)/.well-known/jwks.json",
                idTokenSigningAlgValuesSupported: ["ES256"]
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(liveMetadata),
                tokenEndpointAuthMethod: .none,
                postLoginRedirectPath: "/default-home",
                idTokenSignedResponseAlg: "ES256",
                allowInsecureTransport: true
            )

            // Pre-seed the state store with an entry that has returnTo = "/dashboard".
            let persist = MemoryPersistDriver()
            let stateStore = PersistDriverStateStore(persist)
            let seedState = OIDCAuthRequestState(
                state: stateValue,
                nonce: nonce,
                pkceVerifier: "dummy-verifier",
                returnTo: "/dashboard"
            )
            try await stateStore.save(seedState, expiresIn: .seconds(300))

            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = OIDC(configuration: config, stateStore: stateStore, httpClient: httpClient)

            // We need a SessionRequestContext to call callbackSessionHandler.
            // Use the app-test infrastructure by spinning up a real app.
            let appRouter = Router(context: BasicSessionRequestContext<OIDCSessionData, OIDCIdentity>.self)
            let sessionPersist = MemoryPersistDriver()
            appRouter.addMiddleware {
                SessionMiddleware(storage: sessionPersist)
            }
            appRouter.get("/auth/callback") { req, ctx in
                try await oidc.callbackSessionHandler(req, ctx)
            }
            let appWithSession = Application(responder: appRouter.buildResponder())

            try await appWithSession.test(.live) { appClient in
                let resp = try await appClient.execute(
                    uri: "/auth/callback?code=test-code&state=\(stateValue)",
                    method: .get
                )
                #expect(resp.status == .seeOther)
                #expect(resp.headers[.location] == "/dashboard")
            }
        }
    }

    /// When the stored state has no `returnTo`, callbackSessionHandler must redirect to
    /// `configuration.postLoginRedirectPath`.
    @Test func callbackFallsBackToPostLoginRedirectPathWhenNoReturnTo() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key-2")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        struct TestPayload: JWTPayload {
            var iss: IssuerClaim; var sub: SubjectClaim; var aud: AudienceClaim
            var exp: ExpirationClaim; var iat: IssuedAtClaim; var nonce: String?
            func verify(using _: some JWTAlgorithm) async throws {}
        }
        guard let params = privateKey.parameters else { Issue.record("no params"); return }

        let nonce = "nonce-2"
        let stateValue = "state-2"
        let idToken = try await keyCollection.sign(
            TestPayload(
                iss: .init(value: "https://idp.example.com"),
                sub: .init(value: "user-456"),
                aud: .init(value: ["test-client"]),
                exp: .init(value: Date().addingTimeInterval(3600)),
                iat: .init(value: Date()),
                nonce: nonce
            ),
            kid: kid
        )

        let jwksJSON = """
        {"keys":[{"kty":"EC","use":"sig","alg":"ES256","crv":"P-256","kid":"test-key-2","x":"\(params.x)","y":"\(params.y)"}]}
        """
        let tokenResponseJSON = """
        {"access_token":"tok","token_type":"Bearer","id_token":"\(idToken)"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let liveMetadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "http://localhost:\(port)/auth",
                tokenEndpoint: "http://localhost:\(port)/token",
                jwksURI: "http://localhost:\(port)/.well-known/jwks.json",
                idTokenSigningAlgValuesSupported: ["ES256"]
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(liveMetadata),
                tokenEndpointAuthMethod: .none,
                postLoginRedirectPath: "/home",
                idTokenSignedResponseAlg: "ES256",
                allowInsecureTransport: true
            )

            let persist = MemoryPersistDriver()
            let stateStore = PersistDriverStateStore(persist)
            // No returnTo in this state entry.
            let seedState = OIDCAuthRequestState(
                state: stateValue,
                nonce: nonce,
                pkceVerifier: "dummy-verifier"
            )
            try await stateStore.save(seedState, expiresIn: .seconds(300))

            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = OIDC(configuration: config, stateStore: stateStore, httpClient: httpClient)

            let appRouter = Router(context: BasicSessionRequestContext<OIDCSessionData, OIDCIdentity>.self)
            let sessionPersist = MemoryPersistDriver()
            appRouter.addMiddleware {
                SessionMiddleware(storage: sessionPersist)
            }
            appRouter.get("/auth/callback") { req, ctx in
                try await oidc.callbackSessionHandler(req, ctx)
            }
            let appWithSession = Application(responder: appRouter.buildResponder())

            try await appWithSession.test(.live) { appClient in
                let resp = try await appClient.execute(
                    uri: "/auth/callback?code=test-code&state=\(stateValue)",
                    method: .get
                )
                #expect(resp.status == .seeOther)
                #expect(resp.headers[.location] == "/home")
            }
        }
    }
}

// MARK: - Refresh token tests

struct RefreshTokenTests {

    // MARK: - Shared helpers

    /// Builds a signed ES256 ID token using a private key and public JWK params.
    private func makeIDToken(
        issuer: String = "https://idp.example.com",
        subject: String = "user-rt",
        audience: String = "test-client",
        nonce: String? = nil,
        expiresIn: TimeInterval = 3600,
        keys: JWTKeyCollection,
        kid: JWKIdentifier
    ) async throws -> String {
        struct IDTokenPayload: JWTPayload {
            var iss: IssuerClaim; var sub: SubjectClaim; var aud: AudienceClaim
            var exp: ExpirationClaim; var iat: IssuedAtClaim; var nonce: String?
            func verify(using _: some JWTAlgorithm) async throws {}
        }
        return try await keys.sign(
            IDTokenPayload(
                iss: .init(value: issuer),
                sub: .init(value: subject),
                aud: .init(value: [audience]),
                exp: .init(value: Date().addingTimeInterval(expiresIn)),
                iat: .init(value: Date()),
                nonce: nonce
            ),
            kid: kid
        )
    }

    /// Builds JWKS JSON for the given EC public key parameters and kid.
    private func makeJWKSJSON(params: (x: String, y: String), kid: String) -> String {
        """
        {"keys":[{"kty":"EC","use":"sig","alg":"ES256","crv":"P-256","kid":"\(kid)","x":"\(params.x)","y":"\(params.y)"}]}
        """
    }

    /// Creates an `OIDC` instance wired to a live fake IdP server.
    private func makeOIDC(baseURL: String, httpClient: HTTPClient) -> OIDC {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "\(baseURL)/auth",
            tokenEndpoint: "\(baseURL)/token",
            jwksURI: "\(baseURL)/.well-known/jwks.json",
            idTokenSigningAlgValuesSupported: ["ES256"]
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata),
            tokenEndpointAuthMethod: .none,
            idTokenSignedResponseAlg: "ES256",
            allowInsecureTransport: true
        )
        let persist = MemoryPersistDriver()
        return OIDC(
            configuration: config,
            stateStore: PersistDriverStateStore(persist),
            httpClient: httpClient
        )
    }

    /// Returns a previous `OIDCIdentity` to use as the "previousIdentity" argument.
    private func makePreviousIdentity(idToken: String, refreshToken: String = "old-rt") -> OIDCIdentity {
        OIDCIdentity(
            subject: "user-rt",
            issuer: "https://idp.example.com",
            idToken: idToken,
            claims: OIDCClaims(subject: "user-rt", name: nil, givenName: nil, familyName: nil,
                               email: nil, emailVerified: nil, picture: nil, locale: nil, updatedAt: nil),
            accessToken: "old-access-token",
            refreshToken: refreshToken,
            accessTokenExpiresAt: Date().addingTimeInterval(-60)  // expired
        )
    }

    // MARK: - Test 1: refresh returns new identity when id_token present

    @Test func refreshReturnsNewIdentityWhenIdTokenPresent() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-1")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        let newIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-1")
        let tokenResponseJSON = """
        {"access_token":"new-access","id_token":"\(newIDToken)","refresh_token":"new-rt","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            let identity = try await oidc.refreshIdentity(refreshToken: "old-rt")

            #expect(identity.idToken == newIDToken)
            #expect(identity.subject == "user-rt")
            #expect(identity.accessToken == "new-access")
            #expect(identity.refreshToken == "new-rt")
            #expect(identity.accessTokenExpiresAt != nil)
        }
    }

    // MARK: - Test 2: reuses previousIdentity id_token when response omits id_token

    @Test func refreshReusesPreviousIdTokenWhenAbsent() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-2")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        let previousIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-2")
        // No id_token in the response
        let tokenResponseJSON = """
        {"access_token":"new-access-2","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            let previous = makePreviousIdentity(idToken: previousIDToken)
            let identity = try await oidc.refreshIdentity(refreshToken: "old-rt", previousIdentity: previous)

            // idToken must be the one from previousIdentity, not a new one
            #expect(identity.idToken == previousIDToken)
            #expect(identity.subject == previous.subject)
            // New access token from the response
            #expect(identity.accessToken == "new-access-2")
        }
    }

    // MARK: - Test 3: throws when no id_token and no previousIdentity

    @Test func refreshThrowsWhenNoIdTokenAndNoPrevious() async throws {
        let tokenResponseJSON = """
        {"access_token":"new-access-3","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        // JWKS endpoint not needed for this test but add it to avoid 404
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: "{\"keys\":[]}")))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            do {
                _ = try await oidc.refreshIdentity(refreshToken: "old-rt", previousIdentity: nil)
                Issue.record("Expected refreshIdentity to throw when no id_token and no previousIdentity")
            } catch let error as OIDCError {
                // Verify it's the expected providerError with the "missing_id_token" code.
                if case .providerError(let code, _) = error.kind {
                    #expect(code == "missing_id_token")
                } else {
                    Issue.record("Expected providerError(missing_id_token), got \(error)")
                }
            } catch {
                Issue.record("Expected OIDCError, got \(error)")
            }
        }
    }

    // MARK: - Test 4: keeps existing refresh token when response omits one

    @Test func refreshKeepsExistingRefreshTokenWhenAbsent() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-4")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        let previousIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-4")
        // No refresh_token in the response
        let tokenResponseJSON = """
        {"access_token":"new-access-4","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            let previous = makePreviousIdentity(idToken: previousIDToken, refreshToken: "original-rt")
            let identity = try await oidc.refreshIdentity(refreshToken: "original-rt", previousIdentity: previous)

            // Must keep the original refresh token since the response didn't issue a new one
            #expect(identity.refreshToken == "original-rt")
        }
    }

    // MARK: - Test 5: replaces refresh token when response includes one

    @Test func refreshReplacesRefreshTokenWhenPresent() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-5")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        let previousIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-5")
        let tokenResponseJSON = """
        {"access_token":"new-access-5","refresh_token":"brand-new-rt","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            let previous = makePreviousIdentity(idToken: previousIDToken, refreshToken: "original-rt")
            let identity = try await oidc.refreshIdentity(refreshToken: "original-rt", previousIdentity: previous)

            // Must use the new refresh token from the response
            #expect(identity.refreshToken == "brand-new-rt")
        }
    }

    // MARK: - Test 6: verifies new id_token signature (tampered token throws)

    @Test func refreshVerifiesNewIdTokenSignature() async throws {
        let legitimateKey = ES256PrivateKey()
        let attackerKey = ES256PrivateKey()
        let legitimateCollection = JWTKeyCollection()
        let attackerCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-6")
        await legitimateCollection.add(ecdsa: legitimateKey, kid: kid)
        await attackerCollection.add(ecdsa: attackerKey, kid: kid)

        guard let legitimateParams = legitimateKey.parameters else { Issue.record("no params"); return }

        // Sign the token with the ATTACKER key but serve the LEGITIMATE public key in JWKS
        // → signature verification must fail
        let tamperedToken = try await makeIDToken(keys: attackerCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: legitimateParams, kid: "rt-key-6")
        let tokenResponseJSON = """
        {"access_token":"new-access-6","id_token":"\(tamperedToken)","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            await #expect(throws: (any Error).self) {
                _ = try await oidc.refreshIdentity(refreshToken: "old-rt")
            }
        }
    }

    // MARK: - Test 7: authenticator auto-refreshes expired access token

    @Test func authenticatorAutoRefreshesExpiredAccessToken() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-7")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        let oldIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let newIDToken = try await makeIDToken(keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-7")
        let tokenResponseJSON = """
        {"access_token":"refreshed-access","id_token":"\(newIDToken)","refresh_token":"new-rt-7","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let metadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "http://localhost:\(port)/auth",
                tokenEndpoint: "http://localhost:\(port)/token",
                jwksURI: "http://localhost:\(port)/.well-known/jwks.json",
                idTokenSigningAlgValuesSupported: ["ES256"]
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(metadata),
                tokenEndpointAuthMethod: .none,
                idTokenSignedResponseAlg: "ES256",
                allowInsecureTransport: true
            )
            let sessionPersist = MemoryPersistDriver()
            let oidc = OIDC(
                configuration: config,
                stateStore: PersistDriverStateStore(MemoryPersistDriver()),
                httpClient: httpClient
            )

            // Build the app with a /seed endpoint to create a session, and /me to verify it.
            let expiredIdentity = OIDCIdentity(
                subject: "user-rt",
                issuer: "https://idp.example.com",
                idToken: oldIDToken,
                claims: OIDCClaims(subject: "user-rt", name: nil, givenName: nil, familyName: nil,
                                   email: nil, emailVerified: nil, picture: nil, locale: nil, updatedAt: nil),
                accessToken: "old-access",
                refreshToken: "valid-rt",
                accessTokenExpiresAt: Date().addingTimeInterval(-120)  // expired
            )
            let expiredSession = OIDCSessionData(from: expiredIdentity)

            let appRouter = Router(context: BasicSessionRequestContext<OIDCSessionData, OIDCIdentity>.self)
            appRouter.addMiddleware {
                SessionMiddleware(storage: sessionPersist)
            }
            // /seed writes an expired session and returns the Set-Cookie header
            appRouter.get("/seed") { _, ctx -> Response in
                ctx.sessions.setSession(expiredSession)
                return Response(status: .ok)
            }
            appRouter.add(middleware: OIDCSessionAuthenticator(oidc: oidc, autoRefresh: true))
            appRouter.get("/me") { _, ctx -> Response in
                let identity = try ctx.requireIdentity()
                var h = HTTPFields(); h[.contentType] = "text/plain"
                return Response(
                    status: .ok,
                    headers: h,
                    body: .init(byteBuffer: ByteBuffer(string: identity.accessToken ?? "no-token"))
                )
            }
            let appWithSession = Application(responder: appRouter.buildResponder())

            try await appWithSession.test(.live) { appClient in
                // Step 1: seed the session — server writes it and sends back the SESSION_ID cookie.
                let seedResp = try await appClient.execute(uri: "/seed", method: .get)
                #expect(seedResp.status == .ok)
                let setCookieHeader = seedResp.headers[.setCookie]
                // Extract the session cookie value from "SESSION_ID=<value>; ..."
                guard let setCookie = setCookieHeader,
                      let cookieValue = setCookie.split(separator: ";").first.map(String.init),
                      cookieValue.hasPrefix("SESSION_ID=")
                else {
                    Issue.record("No SESSION_ID cookie in /seed response: \(seedResp.headers)")
                    return
                }

                // Step 2: call /me with the session cookie — authenticator should auto-refresh.
                let meResp = try await appClient.execute(
                    uri: "/me",
                    method: .get,
                    headers: [.cookie: cookieValue]
                )
                #expect(meResp.status == .ok)
                let body = String(buffer: meResp.body)
                #expect(body == "refreshed-access")
            }
        }
    }

    // MARK: - Issue 2 (P0): refresh must reject a new id_token whose sub/iss differs

    /// OIDC Core §12: if a new id_token is issued on refresh, its `sub` and `iss`
    /// must equal those of the previous identity.
    @Test func refreshRejectsSubSwappedIdToken() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-sub-swap")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        guard let params = privateKey.parameters else { Issue.record("no params"); return }
        // previousIdentity has subject "user-original"
        let previousIDToken = try await makeIDToken(subject: "user-original", keys: keyCollection, kid: kid)
        // refresh response returns an id_token with a different sub "attacker-user"
        let swappedIDToken = try await makeIDToken(subject: "attacker-user", keys: keyCollection, kid: kid)
        let jwksJSON = makeJWKSJSON(params: params, kid: "rt-key-sub-swap")
        let tokenResponseJSON = """
        {"access_token":"new-access","id_token":"\(swappedIDToken)","expires_in":3600,"token_type":"Bearer"}
        """

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let oidc = makeOIDC(baseURL: "http://localhost:\(port)", httpClient: httpClient)
            let previous = makePreviousIdentity(idToken: previousIDToken)
            // sub differs → must throw
            await #expect(throws: OIDCError.idTokenInvalid(.other("refresh sub/iss mismatch"))) {
                _ = try await oidc.refreshIdentity(refreshToken: "old-rt", previousIdentity: previous)
            }
        }
    }

    // MARK: - Test 8: authenticator returns nil on expired token when autoRefresh is false

    @Test func authenticatorWithoutAutoRefreshReturnsNilOnExpiredToken() async throws {
        let privateKey = ES256PrivateKey()
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "rt-key-8")
        await keyCollection.add(ecdsa: privateKey, kid: kid)

        let oldIDToken = try await makeIDToken(keys: keyCollection, kid: kid)

        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/.well-known/jwks.json"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata),
            tokenEndpointAuthMethod: .none
        )
        let oidc = OIDC(
            configuration: config,
            stateStore: PersistDriverStateStore(MemoryPersistDriver())
        )

        let expiredIdentity = OIDCIdentity(
            subject: "user-rt",
            issuer: "https://idp.example.com",
            idToken: oldIDToken,
            claims: OIDCClaims(subject: "user-rt", name: nil, givenName: nil, familyName: nil,
                               email: nil, emailVerified: nil, picture: nil, locale: nil, updatedAt: nil),
            accessToken: "old-access",
            refreshToken: "valid-rt",
            accessTokenExpiresAt: Date().addingTimeInterval(-120)
        )

        let sessionPersist = MemoryPersistDriver()
        let appRouter = Router(context: BasicSessionRequestContext<OIDCSessionData, OIDCIdentity>.self)
        appRouter.addMiddleware {
            SessionMiddleware(storage: sessionPersist)
        }
        appRouter.get("/seed") { _, ctx -> Response in
            ctx.sessions.setSession(OIDCSessionData(from: expiredIdentity))
            return Response(status: .ok)
        }
        // autoRefresh: false (default) — expired token should cause nil → 401
        appRouter.add(middleware: OIDCSessionAuthenticator(oidc: oidc, autoRefresh: false))
        appRouter.get("/me") { _, ctx -> Response in
            if (try? ctx.requireIdentity()) != nil {
                return Response(status: .ok)
            }
            return Response(status: .unauthorized)
        }
        let appWithSession = Application(responder: appRouter.buildResponder())

        try await appWithSession.test(.live) { appClient in
            // Step 1: seed the expired session.
            let seedResp = try await appClient.execute(uri: "/seed", method: .get)
            #expect(seedResp.status == .ok)
            let setCookieHeader = seedResp.headers[.setCookie]
            guard let setCookie = setCookieHeader,
                  let cookieValue = setCookie.split(separator: ";").first.map(String.init),
                  cookieValue.hasPrefix("SESSION_ID=")
            else {
                Issue.record("No SESSION_ID cookie in /seed response")
                return
            }

            // Step 2: without auto-refresh the authenticator should return nil → 401.
            let resp = try await appClient.execute(
                uri: "/me",
                method: .get,
                headers: [.cookie: cookieValue]
            )
            #expect(resp.status == .unauthorized)
        }
    }
}

// MARK: - Token-type validation tests (Issue 4, P0)

struct TokenTypeValidationTests {

    /// OIDC Core §3.1.3.3: token_type must be Bearer (case-insensitive).
    @Test func rejectsNonBearerTokenType() async throws {
        let tokenResponseJSON = """
        {"access_token":"tok","token_type":"MAC","expires_in":3600}
        """
        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let metadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "http://localhost:\(port)/auth",
                tokenEndpoint: "http://localhost:\(port)/token",
                jwksURI: "http://localhost:\(port)/jwks"
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(metadata),
                tokenEndpointAuthMethod: .none,
                allowInsecureTransport: true
            )
            let oidc = OIDC(
                configuration: config,
                stateStore: PersistDriverStateStore(MemoryPersistDriver()),
                httpClient: httpClient
            )
            do {
                _ = try await oidc.refreshIdentity(refreshToken: "rt")
                Issue.record("Expected error for non-Bearer token_type")
            } catch let err as OIDCError {
                if case .providerError(let code, _) = err.kind {
                    #expect(code == "invalid_token_type")
                } else {
                    Issue.record("Unexpected error kind: \(err)")
                }
            }
        }
    }

    /// token_type missing from the response is also invalid.
    @Test func rejectsMissingTokenType() async throws {
        let tokenResponseJSON = """
        {"access_token":"tok","expires_in":3600}
        """
        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let metadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "http://localhost:\(port)/auth",
                tokenEndpoint: "http://localhost:\(port)/token",
                jwksURI: "http://localhost:\(port)/jwks"
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(metadata),
                tokenEndpointAuthMethod: .none,
                allowInsecureTransport: true
            )
            let oidc = OIDC(
                configuration: config,
                stateStore: PersistDriverStateStore(MemoryPersistDriver()),
                httpClient: httpClient
            )
            do {
                _ = try await oidc.refreshIdentity(refreshToken: "rt")
                Issue.record("Expected error for missing token_type")
            } catch let err as OIDCError {
                if case .providerError(let code, _) = err.kind {
                    #expect(code == "invalid_token_type")
                } else {
                    Issue.record("Unexpected error kind: \(err)")
                }
            }
        }
    }

    /// Bearers with different casing must be accepted.
    @Test func acceptsBearerTokenTypeCaseInsensitive() async throws {
        // Use "bearer" (lowercase) — must be accepted.
        let tokenResponseJSON = """
        {"access_token":"tok","token_type":"bearer","expires_in":3600,"id_token":"placeholder"}
        """
        // This test just checks that TokenExchange doesn't throw for lowercase "bearer".
        // We can verify by calling the token exchange directly.
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            tokenEndpointAuthMethod: .none,
            allowInsecureTransport: true
        )
        let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
        defer { try? httpClient.syncShutdown() }

        let idpRouter = Router()
        idpRouter.post("/token") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: tokenResponseJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let exchange = TokenExchange(
                configuration: config,
                httpClient: httpClient,
                logger: Logger(label: "hummingbird-oidc.test")
            )
            // Should not throw — lowercase "bearer" is valid
            let response = try await exchange.refresh(
                refreshToken: "rt",
                tokenEndpointURL: "http://localhost:\(port)/token"
            )
            #expect(response.tokenType == "bearer")
        }
    }
}

// MARK: - Scope enforcement tests (Issue 6, P1)

struct ScopeEnforcementTests {
    /// OIDC Core §3.1.2.1: the "openid" scope MUST be present.
    @Test func resolveMetadataThrowsWhenOpenIDScopeMissing() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            scopes: ["profile", "email"],  // "openid" intentionally absent
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        do {
            _ = try await oidc.resolveMetadata()
            Issue.record("Expected configurationError for missing openid scope")
        } catch let err as OIDCError {
            if case .configurationError = err.kind { /* expected */ }
            else { Issue.record("Unexpected error kind: \(err)") }
        }
    }

    @Test func resolveMetadataSucceedsWithOpenIDScope() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks"
        )
        // Default scopes include "openid" — must not throw.
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        let resolved = try await oidc.resolveMetadata()
        #expect(resolved.issuer == "https://idp.example.com")
    }
}

// MARK: - TLS enforcement tests (Issue 3, P0)

struct TLSEnforcementTests {

    @Test func rejectsInsecureTokenEndpoint() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "http://idp.example.com/token",  // http:// — insecure
            jwksURI: "https://idp.example.com/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        do {
            _ = try await oidc.resolveMetadata()
            Issue.record("Expected error for http:// token_endpoint")
        } catch let err as OIDCError {
            if case .invalidProviderMetadata = err.kind { /* expected */ }
            else { Issue.record("Unexpected error kind: \(err)") }
        }
    }

    @Test func rejectsInsecureIssuerInConfig() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "http://idp.example.com",
            authorizationEndpoint: "http://idp.example.com/auth",
            tokenEndpoint: "http://idp.example.com/token",
            jwksURI: "http://idp.example.com/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "http://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        do {
            _ = try await oidc.resolveMetadata()
            Issue.record("Expected error for http:// issuer")
        } catch let err as OIDCError {
            if case .invalidProviderMetadata = err.kind { /* expected */ }
            else { Issue.record("Unexpected error kind: \(err)") }
        }
    }

    @Test func allowsInsecureTransportWhenFlagSet() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "http://localhost:8080",
            authorizationEndpoint: "http://localhost:8080/auth",
            tokenEndpoint: "http://localhost:8080/token",
            jwksURI: "http://localhost:8080/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "http://localhost:3000/callback",
            issuer: "http://localhost:8080",
            providerSource: .static(metadata),
            allowInsecureTransport: true
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        let resolved = try await oidc.resolveMetadata()
        #expect(resolved.issuer == "http://localhost:8080")
    }
}

// MARK: - Fix: authorization_endpoint must be HTTPS (was omitted from validateEndpointURLs)

extension TLSEnforcementTests {
    @Test func rejectsInsecureAuthorizationEndpoint() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "http://idp.example.com/auth",  // http:// — insecure
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        do {
            _ = try await oidc.resolveMetadata()
            Issue.record("Expected invalidProviderMetadata for http:// authorization_endpoint")
        } catch let err as OIDCError {
            if case .invalidProviderMetadata = err.kind { /* expected */ }
            else { Issue.record("Unexpected error kind: \(err)") }
        }
    }
}

// MARK: - Fix: state must be validated on the error callback path (RFC 6749 §4.1.2.1)

struct CallbackErrorValidationTests {

    private func makeOIDCWithState(state: String) async throws -> (OIDC, PersistDriverStateStore) {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata)
        )
        let persist = MemoryPersistDriver()
        let store = PersistDriverStateStore(persist)
        let entry = OIDCAuthRequestState(state: state, nonce: "n", pkceVerifier: "v")
        try await store.save(entry, expiresIn: .seconds(300))
        let oidc = OIDC(configuration: config, stateStore: store)
        return (oidc, store)
    }

    private func request(path: String) -> Request {
        Request(
            head: HTTPRequest(method: .get, scheme: "https", authority: "app.example.com", path: path),
            body: .init(buffer: ByteBuffer())
        )
    }

    /// Error callback with no state param → badRequest (state is required for all callbacks).
    @Test func errorCallbackWithNoStateIsBadRequest() async throws {
        let (oidc, _) = try await makeOIDCWithState(state: "valid-state")
        await #expect(throws: HTTPError.self) {
            _ = try await oidc.processCallback(request: request(path: "/callback?error=access_denied"))
        }
    }

    /// Error callback with an unknown state → invalidState, not providerError.
    /// Before the fix the error check fired before state validation; an attacker with no
    /// valid state could inject arbitrary error codes and descriptions.
    @Test func errorCallbackWithInvalidStateIsInvalidState() async throws {
        let (oidc, _) = try await makeOIDCWithState(state: "real-state")
        await #expect(throws: OIDCError.invalidState) {
            _ = try await oidc.processCallback(
                request: request(path: "/callback?error=access_denied&state=forged-state")
            )
        }
    }

    /// Error callback with a VALID state → providerError is thrown AND the state is consumed.
    @Test func errorCallbackWithValidStateThrowsProviderErrorAndConsumesState() async throws {
        let (oidc, store) = try await makeOIDCWithState(state: "valid-state")
        await #expect(throws: OIDCError.providerError(code: "access_denied", description: nil)) {
            _ = try await oidc.processCallback(
                request: request(path: "/callback?error=access_denied&state=valid-state")
            )
        }
        // State must be consumed — replay must fail.
        let replayed = try await store.consume(state: "valid-state")
        #expect(replayed == nil, "State should be consumed after an error callback")
    }
}

// MARK: - Fix: JWTVerifier should only retry JWKS on key-not-found, not on every error

struct JWTVerifierRetryTests {

    /// An actor that counts how many times the JWKS endpoint is fetched.
    private actor FetchCounter {
        private(set) var count = 0
        func increment() { count += 1 }
    }

    /// A token with a bad signature (signed by a different key than the one in JWKS)
    /// must NOT trigger a JWKS refresh, since the failure is a signature mismatch —
    /// not a missing key.
    @Test func badSignatureDoesNotTriggerJWKSRefresh() async throws {
        let legitimateKey = ES256PrivateKey()
        let attackerKey = ES256PrivateKey()
        let legitimateCollection = JWTKeyCollection()
        let attackerCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "jwks-retry-key")
        await legitimateCollection.add(ecdsa: legitimateKey, kid: kid)
        await attackerCollection.add(ecdsa: attackerKey, kid: kid)

        guard let params = legitimateKey.parameters else {
            Issue.record("Could not extract key parameters"); return
        }
        // Token signed with attacker key but JWKS serves legitimate key.
        struct P: JWTPayload {
            var sub: SubjectClaim; var exp: ExpirationClaim; var iat: IssuedAtClaim
            func verify(using _: some JWTAlgorithm) async throws {}
        }
        let tamperedToken = try await attackerCollection.sign(
            P(sub: .init(value: "u"), exp: .init(value: Date().addingTimeInterval(3600)), iat: .init(value: Date())),
            kid: kid
        )

        let jwksJSON = """
        {"keys":[{"kty":"EC","use":"sig","alg":"ES256","crv":"P-256",
          "kid":"jwks-retry-key","x":"\(params.x)","y":"\(params.y)"}]}
        """
        let counter = FetchCounter()
        let idpRouter = Router()
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            await counter.increment()
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { client in
            let port = try #require(client.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let cache = JWKSCache(
                jwksURL: "http://localhost:\(port)/.well-known/jwks.json",
                cacheTTL: .seconds(60),
                httpClient: httpClient
            )
            let verifier = JWTVerifier(jwksCache: cache, allowedAlgorithms: ["ES256"])

            // Must throw OIDCError (not a raw JWTKit error).
            await #expect(throws: OIDCError.self) {
                _ = try await verifier.verify(
                    idToken: tamperedToken,
                    expectedIssuer: "https://idp.example.com",
                    clientID: "client",
                    expectedNonce: nil,
                    clockSkew: .seconds(60)
                )
            }
            // JWKS must be fetched exactly once — no retry for a bad-signature error.
            let fetches = await counter.count
            #expect(fetches == 1, "Bad-signature error must not trigger a JWKS refresh (got \(fetches) fetches)")
        }
    }

    /// Submitting a bad-signature bearer token to OIDCBearerAuthenticator must return nil
    /// (→ 401), not propagate a raw JWTKit error (→ 500).
    @Test func badSignatureBearerTokenReturnsNilNotFiveHundred() async throws {
        let legitimateKey = ES256PrivateKey()
        let attackerKey = ES256PrivateKey()
        let legitimateCollection = JWTKeyCollection()
        let attackerCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "bearer-retry-key")
        await legitimateCollection.add(ecdsa: legitimateKey, kid: kid)
        await attackerCollection.add(ecdsa: attackerKey, kid: kid)
        guard let params = legitimateKey.parameters else {
            Issue.record("no key params"); return
        }
        struct P: JWTPayload {
            var iss: IssuerClaim; var sub: SubjectClaim; var aud: AudienceClaim
            var exp: ExpirationClaim; var iat: IssuedAtClaim
            func verify(using _: some JWTAlgorithm) async throws {}
        }
        let tamperedToken = try await attackerCollection.sign(
            P(iss: .init(value: "https://idp.example.com"),
              sub: .init(value: "u"),
              aud: .init(value: ["test-client"]),
              exp: .init(value: Date().addingTimeInterval(3600)),
              iat: .init(value: Date())),
            kid: kid
        )
        let jwksJSON = """
        {"keys":[{"kty":"EC","use":"sig","alg":"ES256","crv":"P-256",
          "kid":"bearer-retry-key","x":"\(params.x)","y":"\(params.y)"}]}
        """
        let idpRouter = Router()
        idpRouter.get("/.well-known/jwks.json") { _, _ -> Response in
            var h = HTTPFields(); h[.contentType] = "application/json"
            return Response(status: .ok, headers: h, body: .init(byteBuffer: ByteBuffer(string: jwksJSON)))
        }
        let idpApp = Application(responder: idpRouter.buildResponder())

        try await idpApp.test(.live) { idpClient in
            let port = try #require(idpClient.port)
            let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
            defer { try? httpClient.syncShutdown() }

            let metadata = OIDCProviderMetadata(
                issuer: "https://idp.example.com",
                authorizationEndpoint: "https://idp.example.com/auth",
                tokenEndpoint: "https://idp.example.com/token",
                jwksURI: "http://localhost:\(port)/.well-known/jwks.json",
                idTokenSigningAlgValuesSupported: ["ES256"]
            )
            let config = OIDCConfiguration(
                clientID: "test-client",
                redirectURI: "https://app.example.com/callback",
                issuer: "https://idp.example.com",
                providerSource: .static(metadata),
                idTokenSignedResponseAlg: "ES256",
                allowInsecureTransport: true
            )
            let oidc = OIDC(
                configuration: config,
                stateStore: PersistDriverStateStore(MemoryPersistDriver()),
                httpClient: httpClient
            )

            let appRouter = Router(context: BasicAuthRequestContext<OIDCIdentity>.self)
            appRouter.add(middleware: OIDCBearerAuthenticator(oidc: oidc))
            appRouter.get("/me") { _, ctx -> Response in
                if (try? ctx.requireIdentity()) != nil {
                    return Response(status: .ok)
                }
                return Response(status: .unauthorized)
            }
            let app = Application(responder: appRouter.buildResponder())

            try await app.test(.live) { appClient in
                let resp = try await appClient.execute(
                    uri: "/me",
                    method: .get,
                    headers: [.authorization: "Bearer \(tamperedToken)"]
                )
                // Must be 401, NOT 500.
                #expect(resp.status == .unauthorized)
            }
        }
    }
}

// MARK: - Fix: Duration.timeInterval must include sub-second component

struct DurationTimeIntervalTests {
    @Test func millisecondsConvertCorrectly() {
        #expect(Duration.milliseconds(500).timeInterval == 0.5)
        #expect(Duration.milliseconds(100).timeInterval == 0.1)
        #expect(Duration.seconds(5).timeInterval == 5.0)
        #expect(Duration.seconds(0).timeInterval == 0.0)
    }

    /// Clock-skew expressed in milliseconds must actually provide sub-second leeway.
    /// Before the fix, .milliseconds(200).components.seconds == 0, so the skew was zero.
    @Test func subSecondClockSkewIsApplied() throws {
        // Token expired 100 ms ago; skew window is 200 ms → should pass.
        let expiredByHundredMs = Date().addingTimeInterval(-0.1)
        var payload = OIDCIDTokenPayload(
            issuer: IssuerClaim(value: "https://idp.example.com"),
            subject: SubjectClaim(value: "u"),
            audience: AudienceClaim(value: ["client"]),
            expiration: ExpirationClaim(value: expiredByHundredMs),
            issuedAt: IssuedAtClaim(value: Date().addingTimeInterval(-0.2))
        )
        // Should NOT throw: exp is 100 ms ago, skew is 200 ms.
        try payload.verify(
            expectedIssuer: "https://idp.example.com",
            clientID: "client",
            expectedNonce: nil,
            clockSkew: .milliseconds(200)
        )
    }
}

// MARK: - Fix: DiscoveredVerifierCache must use a new JWKSCache when jwks_uri changes

extension IDTokenVerificationTests {
    @Test func resolveVerifierCreatesNewCacheWhenJWKSURIChanges() {
        let metadata1 = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks-v1"
        )
        let metadata2 = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks-v2"
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .discovered
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))

        let v1 = oidc.resolveVerifier(metadata: metadata1)
        let v2 = oidc.resolveVerifier(metadata: metadata2)
        #expect(
            ObjectIdentifier(v1.jwksCache) != ObjectIdentifier(v2.jwksCache),
            "Different jwks_uri must produce different JWKSCache actors"
        )
        // Same URL again → same cache as before.
        let v1Again = oidc.resolveVerifier(metadata: metadata1)
        #expect(
            ObjectIdentifier(v1.jwksCache) == ObjectIdentifier(v1Again.jwksCache),
            "Same jwks_uri must reuse the existing JWKSCache"
        )
    }
}

// MARK: - Fix: idTokenSignedResponseAlg must be in provider's supported list

struct AlgorithmValidationTests {
    @Test func resolveMetadataRejectsUnsupportedAlgorithm() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks",
            idTokenSigningAlgValuesSupported: ["ES256"]
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata),
            idTokenSignedResponseAlg: "RS256"  // not in provider's list
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        do {
            _ = try await oidc.resolveMetadata()
            Issue.record("Expected configurationError for algorithm mismatch")
        } catch let err as OIDCError {
            if case .configurationError = err.kind { /* expected */ }
            else { Issue.record("Unexpected error kind: \(err)") }
        }
    }

    @Test func resolveMetadataAcceptsAlgorithmInSupportedList() async throws {
        let metadata = OIDCProviderMetadata(
            issuer: "https://idp.example.com",
            authorizationEndpoint: "https://idp.example.com/auth",
            tokenEndpoint: "https://idp.example.com/token",
            jwksURI: "https://idp.example.com/jwks",
            idTokenSigningAlgValuesSupported: ["RS256", "ES256"]
        )
        let config = OIDCConfiguration(
            clientID: "test-client",
            redirectURI: "https://app.example.com/callback",
            issuer: "https://idp.example.com",
            providerSource: .static(metadata),
            idTokenSignedResponseAlg: "ES256"
        )
        let oidc = OIDC(configuration: config, stateStore: PersistDriverStateStore(MemoryPersistDriver()))
        let resolved = try await oidc.resolveMetadata()
        #expect(resolved.issuer == "https://idp.example.com")
    }
}

// MARK: - Fix: OIDCIdentity ↔ OIDCSessionData round-trip must preserve all fields

struct IdentitySessionRoundTripTests {
    @Test func allFieldsRoundTripThroughSessionData() {
        let original = OIDCIdentity(
            subject: "user-1",
            issuer: "https://idp.example.com",
            idToken: "id.token.value",
            claims: OIDCClaims(
                subject: "user-1",
                name: "Alice Smith",
                givenName: "Alice",
                familyName: "Smith",
                email: "alice@example.com",
                emailVerified: true,
                picture: "https://example.com/alice.jpg",
                locale: "en-US",
                updatedAt: Date(timeIntervalSinceReferenceDate: 1_000_000)
            ),
            accessToken: "access.token",
            refreshToken: "refresh.token",
            accessTokenExpiresAt: Date(timeIntervalSinceReferenceDate: 2_000_000)
        )
        let session = OIDCSessionData(from: original)
        let roundTripped = OIDCIdentity(from: session)

        #expect(roundTripped.subject == original.subject)
        #expect(roundTripped.issuer == original.issuer)
        #expect(roundTripped.idToken == original.idToken)
        #expect(roundTripped.claims.name == original.claims.name)
        #expect(roundTripped.claims.givenName == original.claims.givenName)
        #expect(roundTripped.claims.familyName == original.claims.familyName)
        #expect(roundTripped.claims.email == original.claims.email)
        #expect(roundTripped.claims.emailVerified == original.claims.emailVerified)
        #expect(roundTripped.claims.picture == original.claims.picture)
        #expect(roundTripped.claims.locale == original.claims.locale)
        #expect(roundTripped.claims.updatedAt == original.claims.updatedAt)
        #expect(roundTripped.accessToken == original.accessToken)
        #expect(roundTripped.refreshToken == original.refreshToken)
        #expect(roundTripped.accessTokenExpiresAt == original.accessTokenExpiresAt)
    }
}

// MARK: - Spy state store (for ReturnToTests)

/// A minimal `OIDCStateStore` that records the last entry saved, for asserting
/// what `handleLogin` stores without needing a full round-trip.
private final class SpyStateStore: OIDCStateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var _lastSaved: OIDCAuthRequestState?

    var lastSaved: OIDCAuthRequestState? {
        lock.withLock { _lastSaved }
    }

    func save(_ entry: OIDCAuthRequestState, expiresIn: Duration) async throws {
        lock.withLock { _lastSaved = entry }
    }

    func consume(state: String) async throws -> OIDCAuthRequestState? { nil }
}
