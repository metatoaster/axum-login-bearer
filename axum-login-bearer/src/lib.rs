use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use axum::http::{header, Request, Response};
use axum_login::{AuthManager, AuthnBackend};
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
    session_manager_layer: SessionManagerLayer<Store, C>,
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
        let store = self.store.clone();
        let config = self.config.clone();

        // Because the inner service can panic until ready, we need to ensure we only
        // use the ready service.
        //
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        // The following is a very naive implementation of a bearer token service provider that is coupled to
        // the layer setup below, which effectively slips this service layer below axum-login's `AuthManager`
        // and above the `SessionManager` that `AuthManager` typically is stacked directly on top of.  
        //
        // Normally when a request comes in, the session layer will use the cookie provided by the underlying
        // `CookieManager` to back a `Session`, where it in turn be used by the `AuthManager`to set up an
        // `AuthSession`, which the user-provided login logic will leverage.  Once the request is handled and
        // passed back down to the `SessionManager`, if the session layer sees the new data being set (e.g. a
        // new login being assigned to the session), it will result in the cookie being updated, and then the
        // cookie layer will ensure a `Set-Cookie` header is sent.  This final step can be undesirable if we
        // only want bearer tokens be used when provided as we may not want a cookie to be set or sent.  This
        // naive implementation hijacks this normal control flow to prevent this, though a better/proper
        // implementation can probably be done using tower's `Either` and `Steer`.
        //
        // In any case, the two places where the hijacking happens are explained below.  The hijacking works
        // simply because the `SessionManager` keeps a copy of the `Session` it has added, and if that isn't
        // modified it won't inform of the changes down to the `CookieManager`.  The modification is prevented
        // by inserting a new `Session` into the extensions, which kicks the previous one out.
        Box::pin(
            async move {
                let value = req.headers()
                    .get(header::AUTHORIZATION);
                if let Some(value) = value {
                    // First condition where the `Session` should be hijacked: if the bearer token is provided
                    // with the request, set up a new `Session` with that id and insert that, which then the
                    // `AuthManager` will use to set up an `AuthSession` with.
                    if let Ok(authorization) = value.to_str() {
                        match authorization.split_once(' ') {
                            Some((name, token)) if name == "Bearer" => {
                                if let Ok(session_id) = config.token_mode.decode_id(token) {
                                    // Only override the session when provided with a valid bearer token.
                                    let session = Session::new(Some(session_id), store, config.expiry);
                                    req.extensions_mut().insert(session);
                                }
                            }
                            _ => (),
                        }
                    }
                } else {
                    // The second condition is when a request is made to the endpoint where a bearer token
                    // may be issued (TODO: this could be a set of endpoints), a new `Session` must be
                    // inserted such that this would then be used and any update will be done to this copy
                    // and not the one tracked by `SessionManager` - this way prevents it from triggering the
                    // cookie to be sent by the `CookieManager`.
                    if Some(req.uri().to_string().as_ref()) == config.new_bearer_endpoint {
                        let session = Session::new(None, store, config.expiry);
                        let token = BearerAuthSession::new(session.clone(), config.token_mode);
                        req.extensions_mut().insert(session);
                        req.extensions_mut().insert(token);
                    }
                }
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
        session_manager_layer: SessionManagerLayer<Store, C>,
    ) -> Self {
        let config = BearerTokenAuthManagerConfig::default();

        Self {
            store: Arc::new(store),
            config,
            session_manager_layer,
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
        self.config.token_mode = TokenMode::Private(key);
        self
    }
}

impl<
    S,
    Store: SessionStore,
    C: CookieController,
    Backend: AuthnBackend,
> Layer<S>
for
    BearerTokenAuthManagerLayer<Store, C, Backend>
{
    type Service = CookieManager<SessionManager<BearerTokenAuthManager<AuthManager<S, Backend>, Store>, Store, C>>;

    fn layer(&self, inner: S) -> Self::Service {
        let login_manager = AuthManager::new(
            inner,
            self.backend.clone(),
            self.config.data_key.unwrap_or("axum-login.data"),
        );
        let bearer_manager = BearerTokenAuthManager {
            inner: login_manager,
            store: self.store.clone(),
            config: self.config.clone(),
        };

        self.session_manager_layer
            .layer(bearer_manager)
    }
}
