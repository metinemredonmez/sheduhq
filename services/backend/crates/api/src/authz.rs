//! Yetkilendirme: kim, hangi organizasyonda, hangi panelde ve bölümde, ne yapabilir (AZ-01).
//!
//! Her kontrol üç şeyi birlikte değerlendirir: üyelik ve rol, kaynağa özel yetki kaydı, ve kurma /
//! kapatma / bypass için o anki erişim penceresi. Organizasyon kimliği istemciden gelir ama tek
//! başına hiçbir yetki vermez; üyelik her istekte veritabanından doğrulanır. Üye olmayan biri
//! organizasyonun ya da panelin var olup olmadığını öğrenemez (404).

use shedu_domain::access::{AccessPolicy, AccessWindow, LocalMoment, Weekday};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    AppState,
    auth::AuthUser,
    db::set_context,
    error::{ApiError, ApiResult},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Owner,
    Admin,
    Member,
    Operator,
}

impl Role {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "operator" => Some(Self::Operator),
            _ => None,
        }
    }

    /// Organizasyonun bütün panellerinde tam yetkili mi?
    pub fn is_manager(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OrgContext {
    pub user: AuthUser,
    pub organization_id: Uuid,
    pub role: Role,
}

/// İşlemi başlatır, kullanıcı ve kiracı bağlamını ayarlar ve üyeliği doğrular.
pub async fn begin(
    state: &AppState,
    user: AuthUser,
    organization_id: Uuid,
) -> ApiResult<(Transaction<'static, Postgres>, OrgContext)> {
    let mut tx = state.db.begin().await?;
    set_context(&mut tx, Some(user.user_id), Some(organization_id)).await?;
    let role: Option<(String,)> =
        sqlx::query_as("SELECT role FROM memberships WHERE user_id = $1 AND organization_id = $2")
            .bind(user.user_id)
            .bind(organization_id)
            .fetch_optional(&mut *tx)
            .await?;
    let role = role
        .and_then(|(role,)| Role::parse(&role))
        .ok_or(ApiError::NotFound)?;
    Ok((
        tx,
        OrgContext {
            user,
            organization_id,
            role,
        },
    ))
}

/// Kullanıcının bir paneldeki yetkileri.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Permissions {
    /// Panel durumunu ve olaylarını görme. Erişim penceresine bağlı değildir, geçerlilik
    /// süresine bağlıdır.
    pub view: bool,
    pub arm: bool,
    pub disarm: bool,
    pub bypass: bool,
}

impl Permissions {
    const ALL: Self = Self {
        view: true,
        arm: true,
        disarm: true,
        bypass: true,
    };
}

type GrantRow = (
    Uuid,
    Option<Uuid>,
    bool,
    bool,
    bool,
    bool,
    bool,
    Option<i64>,
    Option<i64>,
);

/// Bir paneldeki yetkiler. `partition_id` verilirse yalnızca o bölüme (veya panelin bütün
/// bölümlerine) ait yetki kayıtları sayılır; verilmezse paneldeki herhangi bir kayıt sayılır.
pub async fn permissions(
    conn: &mut PgConnection,
    ctx: &OrgContext,
    panel_id: Uuid,
    partition_id: Option<Uuid>,
) -> ApiResult<Permissions> {
    if ctx.role.is_manager() {
        return Ok(Permissions::ALL);
    }

    let grants: Vec<GrantRow> = sqlx::query_as(
        "SELECT id, partition_id, can_view_events, can_arm, can_disarm, can_bypass, always_open,
                extract(epoch FROM valid_from)::bigint, extract(epoch FROM expires_at)::bigint
           FROM access_grants
          WHERE user_id = $1 AND panel_id = $2
            AND ($3::uuid IS NULL OR partition_id IS NULL OR partition_id = $3)",
    )
    .bind(ctx.user.user_id)
    .bind(panel_id)
    .bind(partition_id)
    .fetch_all(&mut *conn)
    .await?;
    if grants.is_empty() {
        return Ok(Permissions::default());
    }

    let moment = local_moment(conn).await?;
    let grant_ids: Vec<Uuid> = grants.iter().map(|g| g.0).collect();
    let windows: Vec<(Uuid, i16, i16, i16)> = sqlx::query_as(
        "SELECT grant_id, day, start_minute, end_minute FROM access_windows WHERE grant_id = ANY($1)",
    )
    .bind(&grant_ids)
    .fetch_all(&mut *conn)
    .await?;

    let mut result = Permissions::default();
    for (id, _, can_view, can_arm, can_disarm, can_bypass, always_open, valid_from, expires_at) in
        grants
    {
        let policy = AccessPolicy {
            valid_from,
            expires_at,
            always_open,
            windows: windows
                .iter()
                .filter(|w| w.0 == id)
                .filter_map(|w| to_window(w.1, w.2, w.3))
                .collect(),
        };
        let valid = AccessPolicy {
            always_open: true,
            ..policy.clone()
        }
        .is_open_at(moment);
        let open = policy.is_open_at(moment);

        result.view |= valid && can_view;
        result.arm |= open && can_arm;
        result.disarm |= open && can_disarm;
        result.bypass |= open && can_bypass;
    }
    Ok(result)
}

/// Kullanıcının görebileceği bölümler. `None`: panelin bütün bölümleri.
pub async fn visible_partitions(
    conn: &mut PgConnection,
    ctx: &OrgContext,
    panel_id: Uuid,
) -> ApiResult<Option<Vec<Uuid>>> {
    if ctx.role.is_manager() {
        return Ok(None);
    }
    let rows: Vec<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT partition_id FROM access_grants
          WHERE user_id = $1 AND panel_id = $2 AND can_view_events
            AND (valid_from IS NULL OR valid_from <= now())
            AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(ctx.user.user_id)
    .bind(panel_id)
    .fetch_all(conn)
    .await?;
    if rows.iter().any(|(partition,)| partition.is_none()) {
        return Ok(None);
    }
    Ok(Some(rows.into_iter().filter_map(|(p,)| p).collect()))
}

/// Organizasyonun saat dilimindeki şu an (erişim pencereleri bu saate göre değerlendirilir).
async fn local_moment(conn: &mut PgConnection) -> ApiResult<LocalMoment> {
    let (unix, day, minute): (i64, i32, i32) = sqlx::query_as(
        "SELECT extract(epoch FROM now())::bigint,
                extract(isodow FROM now() AT TIME ZONE o.time_zone)::int,
                (extract(hour FROM now() AT TIME ZONE o.time_zone) * 60
                 + extract(minute FROM now() AT TIME ZONE o.time_zone))::int
           FROM organizations o WHERE o.id = app_current_org()",
    )
    .fetch_one(conn)
    .await?;
    let day = weekday(day).ok_or(ApiError::Internal)?;
    let minute = u16::try_from(minute).map_err(|_| ApiError::Internal)?;
    Ok(LocalMoment { unix, day, minute })
}

fn weekday(iso: i32) -> Option<Weekday> {
    Some(match iso {
        1 => Weekday::Mon,
        2 => Weekday::Tue,
        3 => Weekday::Wed,
        4 => Weekday::Thu,
        5 => Weekday::Fri,
        6 => Weekday::Sat,
        7 => Weekday::Sun,
        _ => return None,
    })
}

fn to_window(day: i16, start: i16, end: i16) -> Option<AccessWindow> {
    Some(AccessWindow {
        day: weekday(i32::from(day))?,
        start: u16::try_from(start).ok()?,
        end: u16::try_from(end).ok()?,
    })
}

/// Oturum hâlâ geçerli mi? (kullanıcı etkin ve oturum ailesi iptal edilmemiş)
pub async fn session_active(conn: &mut PgConnection, user: AuthUser) -> Result<bool, sqlx::Error> {
    let active: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM users u
          WHERE u.id = $1 AND u.status = 'active'
            AND EXISTS (SELECT 1 FROM refresh_tokens r
                         WHERE r.family_id = $2 AND r.user_id = $1 AND r.revoked_at IS NULL)",
    )
    .bind(user.user_id)
    .bind(user.session_id)
    .fetch_optional(conn)
    .await?;
    Ok(active.is_some())
}
