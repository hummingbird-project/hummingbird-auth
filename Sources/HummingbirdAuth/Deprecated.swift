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

// Below is a list of deprecated symbols with the "HB" prefix. These are available
// temporarily to ease transition from the old symbols that included the "HB"
// prefix to the new ones.
//
// This file will be removed before we do a 2.0 release

@_documentation(visibility: internal) @available(*, deprecated, renamed: "AuthRequestContext")
public typealias HBAuthRequestContext = AuthRequestContext
@_documentation(visibility: internal) @available(*, deprecated, renamed: "BasicAuthRequestContext")
public typealias HBBasicAuthRequestContext = BasicAuthRequestContext
@_documentation(visibility: internal) @available(*, deprecated, renamed: "LoginCache")
public typealias HBLoginCache = LoginCache

@_documentation(visibility: internal) @available(*, deprecated, renamed: "Authenticatable")
public typealias HBAuthenticatable = Authenticatable
@_documentation(visibility: internal) @available(*, deprecated, renamed: "AuthenticatorMiddleware")
public typealias HBAuthenticator = AuthenticatorMiddleware
@_documentation(visibility: internal) @available(*, deprecated, renamed: "SessionMiddleware")
public typealias HBSessionAuthenticator = SessionMiddleware
@_documentation(visibility: internal) @available(*, deprecated, renamed: "SessionStorage")
public typealias HBSessionStorage = SessionStorage
