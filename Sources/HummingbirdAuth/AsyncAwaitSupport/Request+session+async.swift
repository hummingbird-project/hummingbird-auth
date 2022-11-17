//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2022 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if compiler(>=5.5) && canImport(_Concurrency)

import ExtrasBase64
import Foundation
import Hummingbird

@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
extension SessionManager {
    /// save session
    public func save<Session: Codable>(session: Session, expiresIn: TimeAmount) async throws {
        let sessionId = Self.createSessionId()
        // prefix with "hbs."
        try await self.request.application.sessionStorage.driver.set(
            key: "hbs.\(sessionId)",
            value: session,
            expires: expiresIn,
            request: self.request
        ).get()
        setId(sessionId)
    }

    /// load session
    public func load<Session: Codable>(as: Session.Type = Session.self) async throws -> Session? {
        guard let sessionId = getId() else { return nil }
        // prefix with "hbs."
        return try await self.request.application.sessionStorage.driver.get(
            key: "hbs.\(sessionId)", 
            as: Session.self,
            request: self.request
        ).get()
    }
}

#endif // compiler(>=5.5) && canImport(_Concurrency)
