//! # Overview
//!
//! This crate leverages `tower-sessions` and `axum-login` to provide session identification via a bearer
//! token as a `tower` middleware for `axum`.
//!
//! It offers:
//!
//! - **Drop-in replacement of `tower-sessions`**: while taking full advantage of the [`Session`] type that
//!   packages offers, it can be used without its [`SessionManagerLayer`], but also at the same time can be
//!   configured to use alongside with it to support both bearer tokens for API type usage and cookie based
//!   sessions when used with typical browsers.
//! - **Direct integration with `axum-login`**: taking full advantage of tower's layered design, all the
//!   existing workflows involving some underlying `Session` can be achieved as this crate simply reuses as
//!   much of the underlying types as much as possible.
//!
//! # Usage
//!
//! Roughly speaking, if an existing auth service uses [`AuthManagerLayer`] to provide cookie backed sessions,
//! to also allow bearer token authorization, simply do the following:
//!
//! [`AuthManagerLayer`]: axum_login::AuthManagerLayer
//! [`Session`]: tower_sessions::Session
//! [`SessionManagerLayer`]: tower_sessions::SessionManagerLayer
//!
//! ```rust,no_run
//! # use std::collections::HashMap;
//! #
//! # use axum_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone, Default)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use axum::{
//!     routing::{get, post},
//!     Router,
//! };
//! use axum_login::{
//!     login_required,
//!     tower_sessions::{MemoryStore, SessionManagerLayer},
//!     AuthManagerLayerBuilder,
//! };
//! use axum_login_bearer::BearerTokenAuthManagerLayer;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Session layer.
//!     let session_store = MemoryStore::default();
//!     // Note the clone here, the `session_store` will be used later; naturally the bearer tokens may be
//!     // stored elsewhere to keep them separate, but using different keys with private stores is another
//!     // differentiate them.
//!     let session_layer = SessionManagerLayer::new(session_store.clone());
//!
//!     // Auth service.
//!     let backend = Backend::default();
//!
//!     // To enable bearer tokens, instead of:
//!     // let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();
//!
//!     // ... enable the use of BearerTokenAuthManager:
//!     let auth_layer = BearerTokenAuthManagerLayer::new(session_store, backend)
//!         // Use this to also allow the use of cookies like with the typical setup, which will allow the
//!         // other path to pass the session to the `AuthManager`.
//!         .with_session_manager_layer(session_layer)
//!         // When using session layer, ensure the endpoints that may issue bearer tokens don't have the
//!         // sessions handled by the `SessionManagerLayer`.
//!         .with_new_bearer_endpoint("/api/bearer");
//!
//!     let app = Router::new()
//!         // ... various `.route(...)` setup
//!         .layer(auth_layer);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app.into_make_service()).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! Do refer to examples for reference usage, as this is just a rough description of how this might be
//! used.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, header, Request, Response, StatusCode},
};
use axum_login::{AuthManager, AuthnBackend};
#[cfg(any(feature = "signed", feature = "private"))]
use cookie::Key;
use tower::util::Either;
use tower_cookies::CookieManager;
use tower_layer::Layer;
use tower_service::Service;
use tower_sessions::{
    session::Id,
    service::CookieController,
    Expiry, Session, SessionStore, SessionManager, SessionManagerLayer,
};

mod codec;
#[cfg(feature = "private")]
mod private;
#[cfg(feature = "signed")]
mod signed;

pub use codec::{BearerTokenIdCodec, BearerTokenStrCodec};

#[derive(Clone, Debug, Default)]
enum TokenMode {
    #[default]
    Default,
    Custom(Arc<dyn BearerTokenIdCodec + Send + Sync + 'static>),
}

#[derive(Clone, Debug, Default)]
struct BearerTokenAuthManagerConfig {
    expiry: Option<Expiry>,
    data_key: Option<&'static str>,
    new_bearer_endpoint: Option<&'static str>,
    token_mode: TokenMode,
    has_session_manager_layer: bool,
}

/// A thin wrapper around the underlying [`Session`] to provide a helper to encode the token; [`AuthSession`]
/// should still be used for the more extensive features that it offers for the identification,
/// authentication and authorization of users.
///
/// [`Session`]: tower_sessions::Session
/// [`AuthSession`]: axum_login::AuthSession
#[derive(Clone, Debug)]
pub struct BearerTokenSession {
    session: Session,
    token_mode: TokenMode,
}

/// A middleware that provides [`BearerTokenSession`] as a request extension.
#[derive(Clone)]
pub struct BearerTokenAuthManager<S, Store> {
    inner: S,
    store: Arc<Store>,
    config: BearerTokenAuthManagerConfig,
}

/// A middleware that provides [`BearerTokenSession`] as a request extension.
#[derive(Debug, Clone)]
pub struct BearerTokenAuthManagerLayer<
    Store: SessionStore,
    C: CookieController,
    Backend: AuthnBackend,
> {
    store: Arc<Store>,
    config: BearerTokenAuthManagerConfig,
    session_manager_layer: Option<SessionManagerLayer<Store, C>>,
    backend: Backend,
}

impl TokenMode {
    fn encode_id(&self, id: &Id) -> String {
        match self {
            Self::Default => {
                id.to_string()
            }
            Self::Custom(codec) => {
                codec.encode_id(id)
            }
        }
    }

    fn decode_id(&self, s: &str) -> Result<Id, &'static str> {
        match self {
            Self::Default => {
                s.parse::<Id>()
                    .map_err(|_| "cannot decode to id")
            }
            Self::Custom(codec) => {
                codec.decode_id(s)
                    .ok_or("failed to decode to id")
            }
        }
    }
}

impl BearerTokenAuthManagerConfig {
    fn is_bearer_endpoint(&self, uri: &str) -> bool {
        Some(uri) == self.new_bearer_endpoint
    }
}

impl BearerTokenSession {
    fn new(session: Session, token_mode: TokenMode) -> Self {
        BearerTokenSession { session, token_mode }
    }

    /// Encode the underlying session's id into a bearer token that may be sent to the client.
    pub fn encode_token(&self) -> Option<String> {
        self.session.id()
            .as_ref()
            .map(|id| self.token_mode.encode_id(id))
    }

    /// Saves the underlying session to the store; see [`Session::save`].
    ///
    /// [`Session::save`]: tower_sessions::Session::save
    pub async fn save(&self) -> Result<(), tower_sessions::session::Error> {
        self.session.save().await
    }
}

impl<S> FromRequestParts<S> for BearerTokenSession
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<BearerTokenSession>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract `BearerTokenSession`. Is `BearerTokenAuthManagerLayer` enabled for this endpoint?",
        ))
    }
}

impl<S, Store> BearerTokenAuthManager<S, Store>
where
    Store: SessionStore,
{
    pub fn new(inner: S, store: Store) -> Self {
        Self {
            inner,
            store: store.into(),
            config: BearerTokenAuthManagerConfig::default(),
        }
    }
}

impl<ReqBody, ResBody, S, Store: SessionStore> Service<Request<ReqBody>> for BearerTokenAuthManager<S, Store>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Check if this value was already provided or extract it
        let bearer_token_id = req.extensions_mut()
            // be explicit here with types to prevent the next line from potentially forgetting to do the
            // `.unwrap_or`...
            .remove::<BearerTokenId>()
            .unwrap_or_else(|| extract_bearer_token(&req, &self.config).unwrap_or(BearerTokenId(None)));

        // must provide the token to extensions as there may be no other layers below this.
        let id = bearer_token_id.0;
        let session = Session::new(id, self.store.clone(), self.config.clone().expiry);
        let token = BearerTokenSession::new(session.clone(), self.config.token_mode.clone());
        req.extensions_mut().insert(session);
        req.extensions_mut().insert(token);

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(
            async move {
                inner.call(req).await
            }
        )
    }
}

impl<
    Store: SessionStore,
    C: CookieController,
    Backend: AuthnBackend,
> BearerTokenAuthManagerLayer<Store, C, Backend> {
    pub fn new(
        store: Store,
        backend: Backend,
    ) -> Self {
        let config = BearerTokenAuthManagerConfig::default();

        Self {
            store: Arc::new(store),
            config,
            session_manager_layer: None,
            backend,
        }
    }

    /// Configure the expiry of the sessions that will be created by this manager.
    pub fn with_expiry(mut self, expiry: Option<Expiry>) -> Self {
        self.config.expiry = expiry;
        self
    }

    /// Configure the `data_key` that will be passed to the underlying [`AuthManager`].
    ///
    /// [`AuthManager`]: axum_login::AuthManager
    pub fn with_data_key(mut self, data_key: &'static str) -> Self {
        self.config.data_key = Some(data_key);
        self
    }

    /// Configure the endpoint that will be provided with [`BearerTokenSession`] request extension; typically
    /// this is useful for endpoints that deal with the issurance of new bearer tokens.
    pub fn with_new_bearer_endpoint(mut self, new_bearer_endpoint: &'static str) -> Self {
        self.config.new_bearer_endpoint = Some(new_bearer_endpoint);
        self
    }

    /// Configure with a [`SessionManagerLayer`] to enable fallback with cookie-based sessions when bearer
    /// tokens are not in resolved to be usable with the request.
    ///
    /// [`SessionManagerLayer`]: tower_sessions::SessionManagerLayer
    pub fn with_session_manager_layer(mut self, session_manager_layer: SessionManagerLayer<Store, C>) -> Self {
        self.config.has_session_manager_layer = true;
        self.session_manager_layer = Some(session_manager_layer);
        self
    }

    /// Configure a [`BearerTokenIdCodec`] to convert between session id and the bearer tokens that are issued
    /// to the users.
    pub fn with_token_id_codec(mut self, codec: impl BearerTokenIdCodec + Send + Sync + 'static) -> Self {
        self.config.token_mode = TokenMode::Custom(Arc::new(codec));
        self
    }

    #[cfg(feature = "signed")]
    /// Configure a [`BearerTokenIdCodec`] that will sign the session id to make a bearer token, much like
    /// signed cookies from the `cookies` crate.
    pub fn with_signed(mut self, key: Key) -> Self {
        self.config.token_mode = TokenMode::Custom(Arc::new(signed::Signed(key)));
        self
    }

    #[cfg(feature = "private")]
    /// Configure a [`BearerTokenIdCodec`] that will encrypt the session id to make a bearer token, much like
    /// encrypted cookies from the `cookies` crate.
    pub fn with_private(mut self, key: Key) -> Self {
        // using "id" as that's the default for the cookie.
        // shouldn't matter if the key is different to the one that's ultimately assigned to the cookie
        // jar, but this leaves open the possibility of swapping the cookie's value into a bearer token,
        // which should normally not be a desirable thing.
        self.config.token_mode = TokenMode::Custom(Arc::new(private::Private::new("id", key)));
        self
    }
}

impl<
    Store: SessionStore,
    C: CookieController,
    Backend: AuthnBackend,
    S: Clone,
> Layer<S>
for
    BearerTokenAuthManagerLayer<Store, C, Backend>
{
    type Service = Either<
        BearerTokenAuthManager<AuthManager<S, Backend>, Store>,
        AuthPicker<S, Backend, Store, C>,
    >;

    fn layer(&self, inner: S) -> Self::Service {
        let auth_manager = AuthManager::new(
            inner,
            self.backend.clone(),
            self.config.data_key.unwrap_or("axum-login.data"),
        );

        match &self.session_manager_layer {
            Some(session_manager_layer) => {
                let bearer = BearerTokenAuthManager {
                    inner: auth_manager.clone(),
                    store: self.store.clone(),
                    config: self.config.clone(),
                };
                let cookie = session_manager_layer.layer(auth_manager);

                Either::Right(AuthPicker { bearer, cookie })
            }
            None => {
                Either::Left(BearerTokenAuthManager {
                    inner: auth_manager,
                    store: self.store.clone(),
                    config: self.config.clone(),
                })
            }
        }
    }
}

// Internal use to pass token ids between layers where applicable.
#[derive(Clone, Debug)]
struct BearerTokenId(Option<Id>);

// Selecting different layers is normally the ideal use case for `Steer`, but unfortunately it does not work
// in our case here due to type bounds being specified with a `Request` due to the `Picker` showing up as
// part of the type signature, which renders it being incompatible when being applied to a `Router`.  For
// example, this was tried:
//
// ```
// impl<Store: SessionStore, C: CookieController, Backend: AuthnBackend, S: Clone> Layer<S>
// for
//     BearerTokenAuthManagerLayer<Store, C, Backend>
// {
//     type Service = Either<
//         BearerTokenAuthManager<AuthManager<S, Backend>, Store>,
//         Steer<S, fn(&Request<ReqBody>, &[S]) -> usize, Request<ReqBody>>,
//     >;
//
//     fn layer(&self, inner: S) -> Self::Service {
//         fn pick<S, ReqBody>(req: &Request<ReqBody>, _services: &[S]) -> usize {
//             ...
// ```
//
// While there weren't any issues with compiling, but upon usage with a `Router`:
//
// ```
// error[E0277]: `dyn HttpBody<Data = Bytes, Error = Error> + Send` cannot be shared between threads safely
//    --> examples/sqlite-bearer/src/web/app.rs:71:20
//     |
// 71  |             .layer(auth_layer);
//     |              ----- ^^^^^^^^^^ `dyn HttpBody<Data = Bytes, Error = Error> + Send` cannot be shared between threads safely
// ```
//
// That's due to the need to have the underlying Request type exposed at the layer level, even though that
// normally doesn't come into play until later.
//
// Perhaps there may be another way around this but the author was unable to try it, but instead opted for
// a custom struct with only the immediately neede things laid out given the relative simplicity of only
// having two stacks to pick from.

/// A layer for steering an incoming request, depending on its contents, to the desired layer that tracks a
/// session, either using a cookie or a bearer token.
///
/// This is set up by the [`BearerTokenAuthManagerLayer`] if a [`SessionManagerLayer`] is configured with it.
/// The heuristics for determining which stack to use is it will first check the request for an authorization
/// header and whether or not its authentication scheme is `Bearer`.  Should no authorization header be found
/// then it checks whether or not if the incoming uri points to a bearer endpoint.  If either conditions are
/// true the [`BearerTokenAuthManager`] will be used to, otherwise the [`SessionManager`] will be used
/// instead.
///
/// [`SessionManagerLayer`]: tower_sessions::SessionManagerLayer
/// [`SessionManager`]: tower_sessions::SessionManager
#[derive(Clone)]
pub struct AuthPicker<S, Backend: AuthnBackend, Store: SessionStore, C: CookieController> {
    bearer: BearerTokenAuthManager<AuthManager<S, Backend>, Store>,
    cookie: CookieManager<SessionManager<AuthManager<S, Backend>, Store, C>>,
}

fn extract_bearer_token<ReqBody>(
    req: &Request<ReqBody>,
    config: &BearerTokenAuthManagerConfig,
) -> Option<BearerTokenId> {
    let value = req.headers()
        .get(header::AUTHORIZATION);
    if let Some(value) = value {
        // When an authorization with `Bearer` is provided, assume the bearer workflow.
        if let Ok(authorization) = value.to_str() {
            if let Some((name, token)) = authorization.split_once(' ') && name == "Bearer" {
                return Some(BearerTokenId(config.token_mode.decode_id(token).ok()));
            }
        }
    } else {
        // Alternatively, if the request uri points to a bearer endpoint as per the configuration, mark it as
        // such by returning some `BearerTokenId` with a `None`.  This configuration is provided as such to
        // help the picker disambiguate between whether to go down ehter the `BearerTokenAuth` or the
        // `CookieManager` path as required.  This avoids placing the onus of having to provide some empty
        // `Bearer` prefixed authorization on the user, as otherwise the cookie stack may be activated
        // instead.
        if config.is_bearer_endpoint(req.uri().to_string().as_ref()) {
            return Some(BearerTokenId(None));
        }
    }
    None
}

impl<
    ReqBody,
    ResBody,
    S,
    Store: SessionStore + Clone,
    Backend: AuthnBackend + 'static,
    C: CookieController,
> Service<Request<ReqBody>> for AuthPicker<S, Backend, Store, C>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.bearer.poll_ready(cx)?.is_pending() {
            return Poll::Pending
        }
        self.cookie.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        if let Some(bearer_token_id) = extract_bearer_token(&req, &self.bearer.config) {
            req.extensions_mut().insert(bearer_token_id);
            let clone = self.bearer.clone();
            let mut inner = std::mem::replace(&mut self.bearer, clone);
            Box::pin(
                async move {
                    inner.call(req).await
                }
            )
        } else {
            let clone = self.cookie.clone();
            let mut inner = std::mem::replace(&mut self.cookie, clone);
            Box::pin(
                async move {
                    inner.call(req).await
                }
            )
        }
    }
}
