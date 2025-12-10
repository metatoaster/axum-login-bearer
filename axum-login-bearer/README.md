# axum-login-bearer

Leverage well-established patterns provided by `axum-login`, but also
with bearer tokens.

## Overview

This crate provides a middleware that sets up a new layer under the
`AuthManager` from `axum-login` crate that will provide an alternative
`Session` that is detached from an underlying `SessionManager` from the
`tower-sessions` crate when conditions meeting the use of a bearer token
are met, such that those sessions won't be associated with a cookie but
will still be managed by some underlying `SessionStore` used by the
`AuthManager`.  The end result is that a bearer token provided with a
request will be able to function in place of the session cookie to
identify the user's session.

There are configuration options that changes how it behaves, please
refer to the examples and documentation (TODO).
