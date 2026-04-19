//! OpenID Connect (authorization code + PKCE) for the management UI.

use dashmap::DashMap;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata,
};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Pending OAuth state between `/login` redirect and `/callback`.
pub struct PendingAuth {
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
    pub created_at: Instant,
}

/// Runtime OIDC configuration + in-memory CSRF/PKCE store.
///
/// We rebuild [`CoreClient`] per request from cached provider metadata so the
/// struct can stay concrete without tracking generic endpoint state.
pub struct OidcState {
    provider_metadata: CoreProviderMetadata,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect_uri: RedirectUrl,
    http: reqwest::Client,
    pending: Arc<DashMap<String, PendingAuth>>,
}

impl OidcState {
    /// Discover provider metadata, build client, and start pending-entry TTL cleanup.
    pub async fn discover_and_connect(
        issuer: String,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Arc<Self>, String> {
        let http = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| format!("reqwest client: {e}"))?;

        let issuer_url =
            IssuerUrl::new(issuer).map_err(|e| format!("invalid OIDC_ISSUER: {e}"))?;
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http)
            .await
            .map_err(|e| format!("OIDC discovery failed: {e}"))?;

        let redirect =
            RedirectUrl::new(redirect_uri).map_err(|e| format!("invalid OIDC_REDIRECT_URI: {e}"))?;

        let pending = Arc::new(DashMap::new());
        spawn_pending_cleanup(Arc::clone(&pending));

        Ok(Arc::new(Self {
            provider_metadata,
            client_id: ClientId::new(client_id),
            client_secret: Some(ClientSecret::new(client_secret)),
            redirect_uri: redirect,
            http,
            pending,
        }))
    }

    /// Build the IdP authorization URL and record CSRF `state` + PKCE verifier.
    pub fn begin_login(&self) -> Result<String, String> {
        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_uri.clone());
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let state_key = csrf_token.secret().clone();
        self.pending.insert(
            state_key,
            PendingAuth {
                nonce,
                pkce_verifier,
                created_at: Instant::now(),
            },
        );

        Ok(auth_url.to_string())
    }

    /// Exchange `code`, validate ID token, return `(session_token, subject)` for logging.
    pub async fn finish_login(
        &self,
        code: &str,
        state: &str,
    ) -> Result<(String, String), OidcFinishError> {
        let pending = self
            .pending
            .remove(state)
            .map(|(_, v)| v)
            .ok_or(OidcFinishError::StateMismatch)?;

        let client = CoreClient::from_provider_metadata(
            self.provider_metadata.clone(),
            self.client_id.clone(),
            self.client_secret.clone(),
        )
        .set_redirect_uri(self.redirect_uri.clone());
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|e| OidcFinishError::ExchangeBuild(e.to_string()))?
            .set_pkce_verifier(pending.pkce_verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| OidcFinishError::TokenRequest(e.to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or(OidcFinishError::MissingIdToken)?;

        let id_token_verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &pending.nonce)
            .map_err(|e| OidcFinishError::Claims(e.to_string()))?;

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg().map_err(|e| OidcFinishError::Claims(e.to_string()))?,
                id_token
                    .signing_key(&id_token_verifier)
                    .map_err(|e| OidcFinishError::Claims(e.to_string()))?,
            )
            .map_err(|e| OidcFinishError::Claims(e.to_string()))?;
            if actual_access_token_hash != *expected_access_token_hash {
                return Err(OidcFinishError::AccessTokenHash);
            }
        }

        let sub = claims.subject().to_string();
        let session = uuid::Uuid::new_v4().to_string();
        Ok((session, sub))
    }

    /// Opportunistically prune stale pending entries (TTL 5 minutes).
    pub fn prune_stale_pending(&self) {
        prune_map(&self.pending, Duration::from_secs(300));
    }
}

fn prune_map(map: &DashMap<String, PendingAuth>, ttl: Duration) {
    let now = Instant::now();
    let stale: Vec<String> = map
        .iter()
        .filter(|e| now.duration_since(e.value().created_at) >= ttl)
        .map(|e| e.key().clone())
        .collect();
    for k in stale {
        map.remove(&k);
    }
}

fn spawn_pending_cleanup(map: Arc<DashMap<String, PendingAuth>>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            prune_map(&map, Duration::from_secs(300));
        }
    });
}

#[derive(Debug)]
pub enum OidcFinishError {
    StateMismatch,
    ExchangeBuild(String),
    TokenRequest(String),
    MissingIdToken,
    Claims(String),
    AccessTokenHash,
}

impl std::fmt::Display for OidcFinishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateMismatch => write!(f, "state_mismatch"),
            Self::ExchangeBuild(s) => write!(f, "exchange_build:{s}"),
            Self::TokenRequest(s) => write!(f, "token_request:{s}"),
            Self::MissingIdToken => write!(f, "missing_id_token"),
            Self::Claims(s) => write!(f, "claims:{s}"),
            Self::AccessTokenHash => write!(f, "access_token_hash"),
        }
    }
}
