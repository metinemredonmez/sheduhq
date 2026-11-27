//! Giriş ve oturum.

pub mod codes;
pub mod extract;
pub(crate) mod handlers;
pub mod mfa;
pub mod password;
pub mod profile;
pub mod rate_limit;
pub mod reauth;
pub mod tokens;
pub mod totp;

use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::AppState;

pub use extract::AuthUser;
pub(crate) use handlers::normalize_phone;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/register/start", post(handlers::register_start))
        .route("/auth/register/complete", post(handlers::register_complete))
        .route("/auth/login", post(handlers::login))
        .route("/auth/refresh", post(handlers::refresh))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/sessions", get(handlers::list_sessions))
        .route("/auth/sessions/{id}", delete(handlers::revoke_session))
        .route("/auth/password-reset/start", post(handlers::reset_start))
        .route(
            "/auth/password-reset/complete",
            post(handlers::reset_complete),
        )
        .route("/me", get(handlers::me).patch(profile::update))
        .route("/me/phone/start", post(profile::phone_start))
        .route("/me/phone/complete", post(profile::phone_complete))
        .route("/auth/mfa", get(mfa::status))
        .route("/auth/mfa/totp/setup", post(mfa::setup))
        .route("/auth/mfa/totp/confirm", post(mfa::confirm))
        .route("/auth/mfa/totp/disable", post(mfa::disable))
        .route(
            "/auth/mfa/recovery-codes",
            post(mfa::regenerate_recovery_codes),
        )
        .route("/auth/mfa/verify", post(mfa::verify))
}
