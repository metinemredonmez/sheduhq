//! Giriş ve oturum.

pub mod codes;
pub mod extract;
mod handlers;
pub mod password;
pub mod rate_limit;
pub mod reauth;
pub mod tokens;

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
        .route("/me", get(handlers::me))
}
