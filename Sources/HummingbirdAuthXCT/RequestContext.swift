//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2023 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HummingbirdAuth
import HummingbirdXCT
import Logging
import NIOCore

public struct HBTestAuthRouterContext: HBAuthRequestContextProtocol, HBTestRouterContextProtocol {
    public init(applicationContext: HBApplicationContext, eventLoop: EventLoop, logger: Logger) {
        self.coreContext = .init(applicationContext: applicationContext, eventLoop: eventLoop, logger: logger)
        self.auth = .init()
    }

    /// core context
    public var coreContext: HBCoreRequestContext
    /// login cache
    public var auth: HBLoginCache
}
