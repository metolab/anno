//! Admin-plane authentication state. Extracted from `AppState` so that
//! password verification (a blocking-pool job) and the in-memory session
//! token live in one place with a tight surface.
//!
//! There is still only one live admin session at a time: a new successful
//! login overwrites the previous token. TTL / multi-session was explicitly
//! out of scope for this refactor.

use crate::state::AuthModeKind;
use std::sync::RwLock;

/// Thin wrapper over an `RwLock<Option<String>>` for the current admin
/// bearer token + an optional bcrypt hash for password verification.
pub struct AuthService {
    auth_mode: AuthModeKind,
    password_hash: Option<String>,
    current_token: RwLock<Option<String>>,
}

/// Error returned by `verify_password`.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("password auth not configured on this server")]
    NotConfigured,
    #[error("bcrypt join error")]
    BcryptJoin,
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
}

impl AuthService {
    pub fn new(auth_mode: AuthModeKind, password_hash: Option<String>) -> Self {
        Self {
            auth_mode,
            password_hash,
            current_token: RwLock::new(None),
        }
    }

    /// Whether any authentication method is configured.
    pub fn needs_auth(&self) -> bool {
        matches!(
            self.auth_mode,
            AuthModeKind::Password | AuthModeKind::Oidc
        )
    }

    /// Install a new session token, replacing any previous one.
    pub fn set_token(&self, token: String) {
        let mut guard = self.current_token.write().unwrap();
        *guard = Some(token);
    }

    /// Constant-time-ish check against the installed session token.
    pub fn verify_token(&self, token: &str) -> bool {
        let guard = self.current_token.read().unwrap();
        guard.as_deref() == Some(token)
    }

    /// Verify `password` against the configured bcrypt hash. bcrypt is
    /// intentionally slow (≥10ms at the default cost of 12), so we always
    /// run it on the blocking pool to avoid stalling the async reactor.
    pub async fn verify_password(&self, password: &str) -> Result<bool, AuthError> {
        if self.auth_mode != AuthModeKind::Password {
            return Err(AuthError::NotConfigured);
        }
        let hash = self.password_hash.as_deref().ok_or(AuthError::NotConfigured)?;
        let hash = hash.to_string();
        let password = password.to_string();
        let res = tokio::task::spawn_blocking(move || bcrypt::verify(&password, &hash))
            .await
            .map_err(|_| AuthError::BcryptJoin)?;
        Ok(res?)
    }
}
