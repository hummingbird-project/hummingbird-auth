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

extension Duration {
    /// Converts to `TimeInterval` (seconds as `Double`), preserving sub-second precision.
    ///
    /// `Duration.components` is `(seconds: Int64, attoseconds: Int64)`.
    /// Using only `.seconds` silently truncates any sub-second value to zero —
    /// e.g. `.milliseconds(500).components.seconds == 0`.
    var timeInterval: TimeInterval {
        let (seconds, attoseconds) = components
        return TimeInterval(seconds) + TimeInterval(attoseconds) * 1e-18
    }
}
