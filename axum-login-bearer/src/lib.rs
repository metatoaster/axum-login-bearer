use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use axum::http::{header, Request, Response};
use axum_login::{AuthManager, AuthnBackend};
use tower::util::Either;
use tower_cookies::CookieManager;
#[cfg(any(feature = "signed", feature = "private"))]
use tower_cookies::Key;
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

#[derive(Clone, Debug)]
pub struct BearerAuthSession {
    session: Session,
    token_mode: TokenMode,
}

#[derive(Clone)]
pub struct BearerTokenAuthManager<S, Store> {
    inner: S,
    store: Arc<Store>,
    config: BearerTokenAuthManagerConfig,
}

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

impl BearerAuthSession {
    fn new(session: Session, token_mode: TokenMode) -> Self {
        BearerAuthSession { session, token_mode }
    }

    /// Encode the underlying session into a bearer token that may be sent to the client.
    pub fn encode_token(&self) -> Option<String> {
        self.session.id()
            .as_ref()
            .map(|id| self.token_mode.encode_id(id))
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
        let token = BearerAuthSession::new(session.clone(), self.config.token_mode.clone());
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

    pub fn with_expiry(mut self, expiry: Option<Expiry>) -> Self {
        self.config.expiry = expiry;
        self
    }

    pub fn with_data_key(mut self, data_key: &'static str) -> Self {
        self.config.data_key = Some(data_key);
        self
    }

    pub fn with_new_bearer_endpoint(mut self, new_bearer_endpoint: &'static str) -> Self {
        self.config.new_bearer_endpoint = Some(new_bearer_endpoint);
        self
    }

    /// Configure this `BearerTokenManagerLayer` with a `SessionManagerLayer` to enable
    /// fallback with cookie-based sessions when Bearer tokens are not available.
    pub fn with_session_manager_layer(mut self, session_manager_layer: SessionManagerLayer<Store, C>) -> Self {
        self.config.has_session_manager_layer = true;
        self.session_manager_layer = Some(session_manager_layer);
        self
    }

    pub fn with_token_id_codec(mut self, codec: impl BearerTokenIdCodec + Send + Sync + 'static) -> Self {
        self.config.token_mode = TokenMode::Custom(Arc::new(codec));
        self
    }

    #[cfg(feature = "signed")]
    pub fn with_signed(mut self, key: Key) -> Self {
        self.config.token_mode = TokenMode::Custom(Arc::new(signed::Signed(key)));
        self
    }

    #[cfg(feature = "private")]
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

// Selecting different layers is normally the ideal use case for `Steer, but unfortunately it does not work
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
// error[E0277]: `dyn HttpBody<Data = Bytes, Error = Error> + Send` cannot be shared between threads safely
//    --> examples/sqlite-bearer/src/web/app.rs:71:20
//     |
// 71  |             .layer(auth_layer);
//     |              ----- ^^^^^^^^^^ `dyn HttpBody<Data = Bytes, Error = Error> + Send` cannot be shared between threads safely
//
// That's due to the need to have the underlying Request type exposed at the layer level, even though that
// normally doesn't come into play until later.
//
// Perhaps there may be another way around this but the author was unable to try it, but instead opted for
// a custom struct with only the immediately neede things laid out given the relative simplicity of only
// having two stacks to pick from.

/// This provides a service that discriminates between auth sessions tracked by cookie backed and bearer token
/// backed sessions.
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
