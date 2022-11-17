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

import Hummingbird

extension HBApplication {
    /// Accessor for session storage
    public var sessionStorage: Persist {
        self.extensions.get(
            \.sessionStorage,
            error: "To use session storage you need to set it up with `HBApplication.addSessions`."
        )
    }

    /// Add session management to `HBApplication`.
    /// - Parameters:
    ///   - storage: Factory struct that will create the persist driver for session storage
    ///   - sessionID: Where session id is stored in request/response
    public func addSessions(
        using storage: HBPersistDriverFactory,
        sessionID: SessionManager.SessionIDStorage = .cookie("HB_SESSION_ID")
    ) {
        SessionManager.sessionID = sessionID
        self.extensions.set(\.sessionStorage, value: .init(storage, application: self)) { persist in
            persist.driver.shutdown()
        }
    }

    /// Add session management to `HBApplication` using default persist memory driver
    /// - Parameter sessionID: Where session id is stored in request/response
    public func addSessions(
        sessionID: SessionManager.SessionIDStorage = .cookie("HB_SESSION_ID")
    ) {
        SessionManager.sessionID = sessionID
        self.extensions.set(\.sessionStorage, value: self.persist)
    }
}
