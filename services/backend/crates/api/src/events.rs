//! Anlık olay akışı (WebSocket).
//!
//! Veritabanı `shedu_events` kanalına yalnızca kimlik içeren bildirimler gönderir; her API kopyası
//! bunları dinler ve bağlı istemcilere dağıtır. Her mesaj, gönderilmeden önce o istemcinin kendi
//! yetkisiyle (RLS altında) yeniden okunur; istemci yalnızca görmeye yetkili olduğunu alır (API-04).
//!
//! - Kimlik: `Authorization: Bearer` başlığı; token URL'de taşınmaz (SES-01).
//! - Origin: tarayıcıdan gelen bağlantı yalnızca izinli origin'lerden kabul edilir; tarayıcı
//!   istemcileri normalde BFF üzerinden bağlanır.
//! - İptal: her olayda ve dakikada bir oturum kontrol edilir; çıkış yapılmışsa bağlantı kapanır
//!   (SES-04). Üyelik kaldırılırsa da kapanır.
//! - İstemciden gelen mesajlar işlenmez; komutlar yalnızca REST ile gönderilir.

use std::time::Duration;

use axum::{
    Router,
    extract::{
        Path, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code},
    },
    http::{HeaderMap, header},
    response::Response,
    routing::get,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::postgres::PgListener;
use tokio::sync::broadcast::{self, error::RecvError};
use uuid::Uuid;

use crate::{
    AppState,
    auth::AuthUser,
    authz::{self, OrgContext},
    error::{ApiError, ApiResult},
};

pub const CHANNEL: &str = "shedu_events";
const SESSION_CHECK: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Deserialize)]
pub struct OrgEvent {
    pub org: Uuid,
    pub kind: String,
    pub id: String,
    pub panel: Uuid,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/organizations/{org_id}/events", get(connect))
}

/// Veritabanı bildirimlerini dinleyip yayın kanalına aktaran arka plan görevi. Bağlantı koparsa
/// yeniden bağlanır.
pub fn start_listener(state: &AppState) -> tokio::task::JoinHandle<()> {
    let pool = state.db.clone();
    let sender = state.events.clone();
    tokio::spawn(async move {
        loop {
            match PgListener::connect_with(&pool).await {
                Ok(mut listener) => {
                    if let Err(error) = listener.listen(CHANNEL).await {
                        tracing::warn!(?error, "olay kanalı dinlenemedi");
                    } else {
                        loop {
                            match listener.recv().await {
                                Ok(notification) => {
                                    match serde_json::from_str::<OrgEvent>(notification.payload()) {
                                        Ok(event) => {
                                            let _ = sender.send(event);
                                        }
                                        Err(error) => {
                                            tracing::warn!(?error, "olay bildirimi çözülemedi")
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(?error, "olay dinleyicisi koptu");
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(error) => tracing::warn!(?error, "olay dinleyicisi bağlanamadı"),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

pub async fn connect(
    State(state): State<AppState>,
    user: AuthUser,
    Path(org_id): Path<Uuid>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin.to_str().unwrap_or_default();
        if !state
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return Err(ApiError::Forbidden("origin_not_allowed"));
        }
    }
    let (tx, ctx) = authz::begin(&state, user, org_id).await?;
    tx.commit().await?;
    Ok(upgrade.on_upgrade(move |socket| serve(socket, state, ctx)))
}

type CommandRow = (Uuid, Uuid, Uuid, String, String, Option<String>, Uuid);

enum Delivery {
    Send(Value),
    Skip,
    Revoked,
}

async fn serve(socket: WebSocket, state: AppState, ctx: OrgContext) {
    let (mut sink, mut stream) = socket.split();
    let mut events = state.events.subscribe();
    let mut ticker = tokio::time::interval(SESSION_CHECK);
    ticker.tick().await;

    loop {
        tokio::select! {
            received = events.recv() => match received {
                Ok(event) if event.org == ctx.organization_id => match render(&state, &ctx, &event).await {
                    Ok(Delivery::Send(message)) => {
                        if sink.send(Message::Text(message.to_string().into())).await.is_err() {
                            break;
                        }
                    }
                    Ok(Delivery::Skip) => {}
                    Ok(Delivery::Revoked) | Err(_) => {
                        close(&mut sink, "session_ended").await;
                        break;
                    }
                },
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => {
                    // Kaçırılan olaylar var: istemci durumu REST ile yeniden yüklemeli.
                    if sink.send(Message::Text(json!({ "type": "resync" }).to_string().into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Closed) => break,
            },
            _ = ticker.tick() => {
                let active = match state.db.acquire().await {
                    Ok(mut conn) => authz::session_active(&mut conn, ctx.user).await.unwrap_or(false),
                    Err(_) => false,
                };
                if !active {
                    close(&mut sink, "session_ended").await;
                    break;
                }
            }
            incoming = stream.next() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
            },
        }
    }
}

async fn close(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    reason: &'static str,
) {
    let _ = sink
        .send(Message::Close(Some(CloseFrame {
            code: close_code::POLICY,
            reason: reason.into(),
        })))
        .await;
}

/// Olayı bu istemcinin yetkisiyle okur. Oturum veya üyelik bittiyse `Revoked`.
async fn render(state: &AppState, ctx: &OrgContext, event: &OrgEvent) -> ApiResult<Delivery> {
    let (mut tx, fresh) = match authz::begin(state, ctx.user, ctx.organization_id).await {
        Ok(value) => value,
        Err(ApiError::NotFound) => return Ok(Delivery::Revoked),
        Err(error) => return Err(error),
    };
    if !authz::session_active(&mut tx, ctx.user).await? {
        return Ok(Delivery::Revoked);
    }
    let permissions = authz::permissions(&mut tx, &fresh, event.panel, None).await?;

    let message = match event.kind.as_str() {
        "command" => {
            let id: Uuid = event.id.parse().map_err(|_| ApiError::Internal)?;
            let row: Option<CommandRow> = sqlx::query_as(
                "SELECT id, panel_id, partition_id, kind, status, rejection_reason, user_id FROM commands WHERE id = $1 AND organization_id = $2",
            )
            .bind(id)
            .bind(fresh.organization_id)
            .fetch_optional(&mut *tx)
            .await?;
            row.filter(|r| fresh.role.is_manager() || r.6 == fresh.user.user_id).map(
                |(id, panel_id, partition_id, kind, status, reason, _)| {
                    json!({ "type": "command", "id": id, "panel_id": panel_id, "partition_id": partition_id,
                            "kind": kind, "status": status, "rejection_reason": reason })
                },
            )
        }
        "partition" if permissions.view => {
            let id: Uuid = event.id.parse().map_err(|_| ApiError::Internal)?;
            let visible = authz::visible_partitions(&mut tx, &fresh, event.panel).await?;
            if visible.as_ref().is_some_and(|ids| !ids.contains(&id)) {
                None
            } else {
                let row: Option<(Uuid, Uuid, i16, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                    "SELECT id, panel_id, number, state, state_changed_at FROM partitions WHERE id = $1 AND organization_id = $2",
                )
                .bind(id)
                .bind(fresh.organization_id)
                .fetch_optional(&mut *tx)
                .await?;
                row.map(|(id, panel_id, number, state, changed)| {
                    json!({ "type": "partition", "id": id, "panel_id": panel_id, "number": number,
                            "state": state, "state_changed_at": changed })
                })
            }
        }
        "panel_event" if permissions.view => {
            let id: i64 = event.id.parse().map_err(|_| ApiError::Internal)?;
            type EventRow = (
                i64,
                Uuid,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<i16>,
                Option<i16>,
                chrono::DateTime<chrono::Utc>,
            );
            let row: Option<EventRow> = sqlx::query_as(
                "SELECT id, panel_id, kind, alarm_kind, arm_mode, priority, partition_number, zone_number, occurred_at
                   FROM panel_events WHERE id = $1 AND organization_id = $2",
            )
            .bind(id)
            .bind(fresh.organization_id)
            .fetch_optional(&mut *tx)
            .await?;
            // Bölüme ait olay yalnızca o bölümü görebilene gider (olay geçmişi, push ve bildirim
            // merkeziyle aynı kural); bölümsüz (panel düzeyi) olaylar paneli gören herkese.
            let row = match row {
                Some(row) if row.6.is_some() => {
                    let visible = authz::visible_partitions(&mut tx, &fresh, event.panel).await?;
                    let allowed = match visible {
                        None => true,
                        Some(ids) => {
                            let numbers: Vec<(i16,)> = sqlx::query_as(
                                "SELECT number FROM partitions WHERE id = ANY($1) AND organization_id = $2",
                            )
                            .bind(&ids)
                            .bind(fresh.organization_id)
                            .fetch_all(&mut *tx)
                            .await?;
                            numbers.iter().any(|(n,)| Some(*n) == row.6)
                        }
                    };
                    allowed.then_some(row)
                }
                other => other,
            };
            row.map(|(id, panel_id, kind, alarm_kind, arm_mode, priority, partition, zone, occurred)| {
                json!({ "type": "panel_event", "id": id, "panel_id": panel_id, "kind": kind,
                        "alarm_kind": alarm_kind, "arm_mode": arm_mode, "priority": priority,
                        "partition_number": partition, "zone_number": zone, "occurred_at": occurred })
            })
        }
        _ => None,
    };
    tx.commit().await?;
    Ok(message.map_or(Delivery::Skip, Delivery::Send))
}

/// Yayın kanalı.
pub fn channel() -> broadcast::Sender<OrgEvent> {
    broadcast::channel(1024).0
}
