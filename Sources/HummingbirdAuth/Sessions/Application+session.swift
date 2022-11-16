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

/// Session Manager Configuration
public struct SessionConfiguration {
    /// Where to store session id
    public var sessionIDStorage: SessionManager.SessionIDStorage {
        get { return SessionManager.sessionIDStorage }
        nonmutating set { SessionManager.sessionIDStorage = newValue }
    }
}

extension HBApplication {
    /// access session info
    public var session: SessionConfiguration { return .init() }
}
