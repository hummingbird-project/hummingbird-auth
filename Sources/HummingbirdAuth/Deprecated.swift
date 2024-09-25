//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2024 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_documentation(visibility: internal) @available(*, unavailable, renamed: "Authenticatable")
public typealias HBAuthenticatable = Authenticatable
@_documentation(visibility: internal) @available(*, unavailable, renamed: "SessionAuthenticator")
public typealias HBSessionAuthenticator = SessionAuthenticator
@_documentation(visibility: internal) @available(*, unavailable, renamed: "SessionStorage")
public typealias HBSessionStorage = SessionStorage

@_documentation(visibility: internal) @available(*, deprecated, renamed: "UserSessionRepository")
public typealias SessionUserRepository = UserSessionRepository
