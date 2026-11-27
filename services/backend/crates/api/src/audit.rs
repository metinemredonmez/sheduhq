//! Denetim kaydı (LOG-01).
//!
//! `details` alanına PIN, token, parola, doğrulama kodu veya telefon numarası yazılmaz (LOG-02).

use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

pub struct Event<'a> {
    pub organization_id: Option<Uuid>,
    pub actor_user_id: Option<Uuid>,
    /// Ör. `auth.login`, `auth.refresh_reuse_detected`.
    pub action: &'static str,
    pub target_type: Option<&'static str>,
    pub target_id: Option<&'a str>,
    pub outcome: Outcome,
    pub details: Value,
}

pub async fn record(conn: &mut PgConnection, event: Event<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (organization_id, actor_user_id, action, target_type, target_id, outcome, details)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(event.organization_id)
    .bind(event.actor_user_id)
    .bind(event.action)
    .bind(event.target_type)
    .bind(event.target_id)
    .bind(event.outcome.as_str())
    .bind(event.details)
    .execute(conn)
    .await?;
    Ok(())
}
