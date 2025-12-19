[![CI](https://github.com/metatoaster/axum-login-bearer/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/metatoaster/axum-login-bearer/actions/workflows/build.yml?query=branch:main)
[![crates.io](https://img.shields.io/crates/v/axum-login-bearer)](https://crates.io/crates/axum-login-bearer/)
[![docs.rs](https://docs.rs/axum-login-bearer/badge.svg)](https://docs.rs/axum-login-bearer/latest/axum-login-bearer/)

# axum-login-bearer

Leverage well-established patterns provided by `axum-login`, but also
with bearer tokens.

## Overview

This crate provides a `BearerTokenAuthManager` that can either operate
on its own, which sets up the `AuthManager` from the `axum-login` crate
to provide the `AuthSession` to provide the familiar interface to deal
with the identification, authentication and authorization of users.  It
can also be set up with the usual `SessionmanagerLayer` to also provide
the typical cookie-backed sessions should both be desired.

The end result is that a bearer token provided with a request will be
able to function in place of the session cookie to identify the user's
session.

There are configuration options that changes how it behaves, please
refer to the documentation and the [sqlite-bearer](
https://github.com/metatoaster/axum-login-bearer/tree/main/examples/sqlite-bearer)
example.
