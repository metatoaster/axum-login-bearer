use tower_sessions::session::Id;

/// This trait converts between the string representation of [`Id`] and some [`String`] suitable for use as a
/// bearer token.
///
/// [`Id`]: tower_sessions::session::Id
pub trait BearerTokenStrCodec {
    /// Invoked by [`BearerTokenIdCodec::encode_id`] with the `Id` formatted.
    ///
    /// This should produce the `String` representation of the bearer token.
    fn encode(&self, id: &str) -> String;

    /// Invoked by [`BearerTokenIdCodec::decode_id`] with the string to be parse into an `Id`.
    ///
    /// This should produce some underlying `String` that may be parsed into an `Id`.  On failure a `None`
    /// should be returned.
    fn decode(&self, s: &str) -> Option<String>;
}

/// This trait converts between [`Id`] and some [`String`] suitable for use as a bearer token.
///
/// Users may wish to implement [`BearerTokenStrCodec`] instead, as this trait provides a blanket
/// implementation for handling the conversion between `Id` and `String` and delegating the resulting value
/// to the underlying implementation.
///
/// [`Id`]: tower_sessions::session::Id
pub trait BearerTokenIdCodec: BearerTokenStrCodec {
    /// Encodes the provided `Id` into some `String`.
    fn encode_id(&self, id: &Id) -> String {
        self.encode(&id.to_string())
    }

    /// Attempt to decode some `String` into an `Id`; on failure, `None` will be returned.
    fn decode_id(&self, s: &str) -> Option<Id> {
        self.decode(&s)?
            .parse::<Id>()
            .ok()
    }
}

impl<T: BearerTokenStrCodec> BearerTokenIdCodec for T {}

mod debug {
    use std::fmt::{Debug, Formatter, Result};
    use super::*;

    impl Debug for (dyn BearerTokenIdCodec + Send + Sync + 'static) {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.debug_struct("BearerTokenIdCodec").finish()
        }
    }
}
