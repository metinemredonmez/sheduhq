//! Platform yöneticisi işlemleri (pilot): müşteri organizasyonu açma, panel atama, olay anında
//! kullanıcıyı kapatma. Yalnızca sunucuda çalışan `shedu-admin` aracı kullanır; API'de karşılığı
//! yoktur (AZ-05, OPS-02).
//!
//! - Araç `shedu_admin` veritabanı rolüyle bağlanır; RLS aynen uygulanır, her işlem kendi
//!   kiracı bağlamında yapılır.
//! - Her değişiklik bir gerekçe ister. İşlemi yapan kişi (sunucudaki kullanıcı adı) ve gerekçe
//!   denetim kaydına yazılır (LOG-01). Telefon numarası denetim kaydına yazılmaz (LOG-02).

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{audit, auth::normalize_phone, db::set_context, error::violated_constraint};

/// Veritabanında yönetici rolünün adı.
pub const ADMIN_ROLE: &str = "shedu_admin";
/// Sanal demo panellerin markası; gerçek panele verilemez.
const RESERVED_BRAND: &str = "shedu-demo";

#[derive(Debug)]
pub enum AdminError {
    Invalid(&'static str),
    NotFound(&'static str),
    Conflict(&'static str),
    Database(sqlx::Error),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(what) => write!(f, "geçersiz: {what}"),
            Self::NotFound(what) => write!(f, "bulunamadı: {what}"),
            Self::Conflict(what) => write!(f, "çakışma: {what}"),
            Self::Database(error) => write!(f, "veritabanı hatası: {error}"),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<sqlx::Error> for AdminError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

pub type AdminResult<T> = Result<T, AdminError>;

/// İşlemi yapan kişi ve gerekçesi.
#[derive(Debug, Clone)]
pub struct Operator {
    name: String,
    reason: String,
}

impl Operator {
    /// `name`: sunucudaki kullanıcı adı. `reason`: en az 10, en fazla 300 karakter.
    pub fn new(name: &str, reason: &str) -> AdminResult<Self> {
        let name = name.trim();
        let valid_name = (1..=64).contains(&name.chars().count())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !valid_name {
            return Err(AdminError::Invalid("işlemi yapan kişi"));
        }
        let reason = reason.trim();
        if !(10..=300).contains(&reason.chars().count()) || reason.chars().any(char::is_control) {
            return Err(AdminError::Invalid("gerekçe (10–300 karakter)"));
        }
        Ok(Self {
            name: name.to_owned(),
            reason: reason.to_owned(),
        })
    }

    fn details(&self, extra: serde_json::Value) -> serde_json::Value {
        let mut details = json!({ "operator": self.name, "reason": self.reason });
        if let (Some(target), Some(source)) = (details.as_object_mut(), extra.as_object()) {
            for (k, v) in source {
                target.insert(k.clone(), v.clone());
            }
        }
        details
    }
}

fn text(value: &str, max: usize, what: &'static str) -> AdminResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(AdminError::Invalid(what));
    }
    Ok(value.to_owned())
}

// ---------------------------------------------------------------------------------------------
// Organizasyon
// ---------------------------------------------------------------------------------------------

pub struct NewOrganization<'a> {
    pub name: &'a str,
    /// `home`, `business` veya `monitoring_center`.
    pub kind: &'a str,
    pub owner_phone: &'a str,
    /// Sahip yeni bir kullanıcıysa görünen adı.
    pub owner_name: &'a str,
}

#[derive(Debug)]
pub struct CreatedOrganization {
    pub organization_id: Uuid,
    pub owner_user_id: Uuid,
    /// Sahip için yeni bir hesap açıldı mı? Açıldıysa kişi parolasını "parola sıfırlama" akışıyla
    /// (SMS kodu) belirler; araç hiçbir zaman parola belirlemez ve göstermez.
    pub owner_created: bool,
}

pub async fn create_organization(
    pool: &PgPool,
    operator: &Operator,
    input: NewOrganization<'_>,
) -> AdminResult<CreatedOrganization> {
    let name = text(input.name, 200, "organizasyon adı")?;
    if !matches!(input.kind, "home" | "business" | "monitoring_center") {
        return Err(AdminError::Invalid("organizasyon türü"));
    }
    let phone =
        normalize_phone(input.owner_phone).ok_or(AdminError::Invalid("sahibin telefonu"))?;

    let organization_id = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;

    let existing: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, status FROM users WHERE phone = $1 FOR UPDATE")
            .bind(&phone)
            .fetch_optional(&mut *tx)
            .await?;
    let (owner_user_id, owner_created) = match existing {
        Some((_, status)) if status != "active" => {
            return Err(AdminError::Conflict("sahibin hesabı etkin değil"));
        }
        Some((id, _)) => (id, false),
        None => {
            let owner_name = text(input.owner_name, 100, "sahibin adı")?;
            let (id,): (Uuid,) = sqlx::query_as(
                "INSERT INTO users (phone, display_name) VALUES ($1, $2) RETURNING id",
            )
            .bind(&phone)
            .bind(&owner_name)
            .fetch_one(&mut *tx)
            .await?;
            (id, true)
        }
    };

    sqlx::query("INSERT INTO organizations (id, name, kind) VALUES ($1, $2, $3)")
        .bind(organization_id)
        .bind(&name)
        .bind(input.kind)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO memberships (user_id, organization_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(owner_user_id)
    .bind(organization_id)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(organization_id),
            actor_user_id: None,
            action: "admin.organization_created",
            target_type: Some("organization"),
            target_id: Some(&organization_id.to_string()),
            outcome: audit::Outcome::Success,
            details: operator.details(json!({
                "kind": input.kind,
                "owner_user_id": owner_user_id,
                "owner_created": owner_created,
            })),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(CreatedOrganization {
        organization_id,
        owner_user_id,
        owner_created,
    })
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct OrganizationSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub members: i64,
    pub panels: i64,
}

/// Bütün organizasyonların özeti; yalnızca yönetici rolüyle çalışır.
pub async fn list_organizations(pool: &PgPool) -> AdminResult<Vec<OrganizationSummary>> {
    Ok(sqlx::query_as("SELECT * FROM admin_organizations()")
        .fetch_all(pool)
        .await?)
}

#[derive(Debug, sqlx::FromRow)]
pub struct MemberLine {
    pub user_id: Uuid,
    pub display_name: String,
    pub phone: Option<String>,
    pub role: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct PanelLine {
    pub id: Uuid,
    pub name: String,
    pub brand: String,
    pub device_serial: String,
    pub connectivity: String,
    pub partitions: i64,
    pub zones: i64,
}

/// Tek organizasyonun ayrıntısı: kendi kiracı bağlamında okunur.
pub async fn show_organization(
    pool: &PgPool,
    organization_id: Uuid,
) -> AdminResult<(OrganizationSummary, Vec<MemberLine>, Vec<PanelLine>)> {
    let mut tx = pool.begin().await?;
    set_context(&mut tx, None, Some(organization_id)).await?;
    let summary: Option<OrganizationSummary> = sqlx::query_as(
        "SELECT o.id, o.name, o.kind, o.created_at,
                (SELECT count(*) FROM memberships m WHERE m.organization_id = o.id) AS members,
                (SELECT count(*) FROM panels p) AS panels
           FROM organizations o WHERE o.id = app_current_org()",
    )
    .fetch_optional(&mut *tx)
    .await?;
    let summary = summary.ok_or(AdminError::NotFound("organizasyon"))?;
    let members: Vec<MemberLine> = sqlx::query_as(
        "SELECT m.user_id, u.display_name, u.phone, m.role
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = $1
          ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, m.created_at",
    )
    .bind(organization_id)
    .fetch_all(&mut *tx)
    .await?;
    let panels: Vec<PanelLine> = sqlx::query_as(
        "SELECT p.id, p.name, p.brand, p.device_serial, p.connectivity,
                (SELECT count(*) FROM partitions pt WHERE pt.panel_id = p.id) AS partitions,
                (SELECT count(*) FROM zones z WHERE z.panel_id = p.id) AS zones
           FROM panels p ORDER BY p.created_at",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((summary, members, panels))
}

// ---------------------------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------------------------

/// Panelin bölüm ve zon düzeni (JSON dosyasından).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelLayout {
    pub partitions: Vec<PartitionSpec>,
    pub zones: Vec<ZoneSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionSpec {
    pub number: i16,
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneSpec {
    pub number: i16,
    pub name: String,
    pub kind: String,
    /// Zonun ait olduğu bölüm numaraları.
    pub partitions: Vec<i16>,
}

impl PanelLayout {
    fn validate(&self) -> AdminResult<()> {
        if self.partitions.is_empty() || self.partitions.len() > 255 {
            return Err(AdminError::Invalid("bölüm listesi (1–255)"));
        }
        let mut numbers = BTreeSet::new();
        for partition in &self.partitions {
            if !(1..=255).contains(&partition.number) || !numbers.insert(partition.number) {
                return Err(AdminError::Invalid("bölüm numarası (1–255, tekil)"));
            }
            text(&partition.name, 100, "bölüm adı")?;
        }
        if self.zones.len() > 9999 {
            return Err(AdminError::Invalid("zon sayısı"));
        }
        let mut zones = BTreeSet::new();
        for zone in &self.zones {
            if !(1..=9999).contains(&zone.number) || !zones.insert(zone.number) {
                return Err(AdminError::Invalid("zon numarası (1–9999, tekil)"));
            }
            text(&zone.name, 100, "zon adı")?;
            if !matches!(
                zone.kind.as_str(),
                "intrusion" | "fire" | "gas" | "flood" | "panic" | "medical" | "tamper" | "other"
            ) {
                return Err(AdminError::Invalid("zon türü"));
            }
            if zone.partitions.is_empty() || !zone.partitions.iter().all(|p| numbers.contains(p)) {
                return Err(AdminError::Invalid(
                    "zonun bölümleri (düzende tanımlı olmalı)",
                ));
            }
        }
        Ok(())
    }
}

pub struct NewPanel<'a> {
    pub organization_id: Uuid,
    pub name: &'a str,
    pub brand: &'a str,
    pub model: Option<&'a str>,
    pub device_serial: &'a str,
    pub layout: &'a PanelLayout,
}

/// Gerçek bir paneli organizasyona atar. Panel çevrimdışı ve "kurmaya hazır değil" başlar;
/// gateway kendini bildirene kadar komut kabul edilmez (EXC-01).
pub async fn add_panel(
    pool: &PgPool,
    operator: &Operator,
    input: NewPanel<'_>,
) -> AdminResult<Uuid> {
    let name = text(input.name, 100, "panel adı")?;
    let brand = text(input.brand, 50, "marka")?;
    if brand.eq_ignore_ascii_case(RESERVED_BRAND) {
        return Err(AdminError::Invalid("marka (demo panellere ayrılmış)"));
    }
    let model = input.model.map(|m| text(m, 50, "model")).transpose()?;
    let serial = text(input.device_serial, 100, "seri numarası")?;
    input.layout.validate()?;

    let mut tx = pool.begin().await?;
    set_context(&mut tx, None, Some(input.organization_id)).await?;
    let org: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM organizations WHERE id = app_current_org()")
            .fetch_optional(&mut *tx)
            .await?;
    if org.is_none() {
        return Err(AdminError::NotFound("organizasyon"));
    }

    let panel_id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO panels (id, organization_id, name, brand, model, device_serial)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(panel_id)
    .bind(input.organization_id)
    .bind(&name)
    .bind(&brand)
    .bind(&model)
    .bind(&serial)
    .execute(&mut *tx)
    .await;
    if let Err(error) = inserted {
        if violated_constraint(&error).as_deref() == Some("panels_brand_device_serial_key") {
            return Err(AdminError::Conflict(
                "bu marka ve seri numarasıyla panel zaten var",
            ));
        }
        return Err(error.into());
    }

    let mut partition_ids = std::collections::BTreeMap::new();
    for partition in &input.layout.partitions {
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO partitions (organization_id, panel_id, number, name)
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(input.organization_id)
        .bind(panel_id)
        .bind(partition.number)
        .bind(partition.name.trim())
        .fetch_one(&mut *tx)
        .await?;
        partition_ids.insert(partition.number, id);
    }
    for zone in &input.layout.zones {
        let (zone_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO zones (organization_id, panel_id, number, name, kind)
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(input.organization_id)
        .bind(panel_id)
        .bind(zone.number)
        .bind(zone.name.trim())
        .bind(&zone.kind)
        .fetch_one(&mut *tx)
        .await?;
        for number in zone.partitions.iter().collect::<BTreeSet<_>>() {
            let partition_id = partition_ids
                .get(number)
                .ok_or(AdminError::Invalid("zonun bölümü"))?;
            sqlx::query(
                "INSERT INTO zone_partitions (organization_id, panel_id, zone_id, partition_id)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(input.organization_id)
            .bind(panel_id)
            .bind(zone_id)
            .bind(partition_id)
            .execute(&mut *tx)
            .await?;
        }
    }

    audit::record(
        &mut tx,
        audit::Event {
            organization_id: Some(input.organization_id),
            actor_user_id: None,
            action: "admin.panel_added",
            target_type: Some("panel"),
            target_id: Some(&panel_id.to_string()),
            outcome: audit::Outcome::Success,
            details: operator.details(json!({
                "brand": brand,
                "partitions": input.layout.partitions.len(),
                "zones": input.layout.zones.len(),
            })),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(panel_id)
}

// ---------------------------------------------------------------------------------------------
// Kullanıcı
// ---------------------------------------------------------------------------------------------

/// Kullanıcıyı kapatır (`active = false`) veya yeniden açar. Kapatma bütün oturumları ve push
/// token'larını hemen iptal eder (SES-04); kişi giriş yapamaz, bildirim almaz. Silme bekleyen
/// veya silinmiş hesaba uygulanmaz.
pub async fn set_user_active(
    pool: &PgPool,
    operator: &Operator,
    phone: &str,
    active: bool,
) -> AdminResult<Uuid> {
    let phone = normalize_phone(phone).ok_or(AdminError::Invalid("telefon"))?;
    let mut tx = pool.begin().await?;
    let user: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, status FROM users WHERE phone = $1 FOR UPDATE")
            .bind(&phone)
            .fetch_optional(&mut *tx)
            .await?;
    let (user_id, status) = user.ok_or(AdminError::NotFound("kullanıcı"))?;
    let (from, to) = if active {
        ("disabled", "active")
    } else {
        ("active", "disabled")
    };
    if status != from {
        return Err(AdminError::Conflict(if active {
            "kullanıcı kapalı değil"
        } else {
            "kullanıcı etkin değil"
        }));
    }
    sqlx::query("UPDATE users SET status = $2, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .bind(to)
        .execute(&mut *tx)
        .await?;
    let mut revoked = 0;
    if !active {
        revoked = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query("UPDATE user_devices SET push_token = NULL WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    audit::record(
        &mut tx,
        audit::Event {
            organization_id: None,
            actor_user_id: None,
            action: if active {
                "admin.user_enabled"
            } else {
                "admin.user_disabled"
            },
            target_type: Some("user"),
            target_id: Some(&user_id.to_string()),
            outcome: audit::Outcome::Success,
            details: operator.details(json!({ "revoked_tokens": revoked })),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_needs_a_clean_name_and_a_real_reason() {
        assert!(Operator::new("ayse.k", "Pilot müşteri kurulumu").is_ok());
        assert!(Operator::new("", "Pilot müşteri kurulumu").is_err());
        assert!(Operator::new("ayşe k", "Pilot müşteri kurulumu").is_err());
        assert!(Operator::new("ayse", "kısa").is_err());
        assert!(Operator::new("ayse", "satır\natlatan gerekçe metni").is_err());
    }

    fn layout(json: serde_json::Value) -> AdminResult<()> {
        serde_json::from_value::<PanelLayout>(json)
            .map_err(|_| AdminError::Invalid("json"))?
            .validate()
    }

    #[test]
    fn layout_rules() {
        let ok = json!({
            "partitions": [{ "number": 1, "name": "Ev" }, { "number": 2, "name": "Garaj" }],
            "zones": [{ "number": 1, "name": "Kapı", "kind": "intrusion", "partitions": [1, 2] }]
        });
        assert!(layout(ok).is_ok());
        for bad in [
            json!({ "partitions": [], "zones": [] }),
            json!({ "partitions": [{ "number": 1, "name": "A" }, { "number": 1, "name": "B" }], "zones": [] }),
            json!({ "partitions": [{ "number": 0, "name": "A" }], "zones": [] }),
            json!({ "partitions": [{ "number": 1, "name": "A" }],
                    "zones": [{ "number": 1, "name": "Z", "kind": "intrusion", "partitions": [2] }] }),
            json!({ "partitions": [{ "number": 1, "name": "A" }],
                    "zones": [{ "number": 1, "name": "Z", "kind": "lazer", "partitions": [1] }] }),
            json!({ "partitions": [{ "number": 1, "name": "A" }],
                    "zones": [{ "number": 1, "name": "Z", "kind": "fire", "partitions": [] }] }),
            json!({ "partitions": [{ "number": 1, "name": "A", "pin": "1234" }], "zones": [] }),
        ] {
            assert!(layout(bad.clone()).is_err(), "{bad}");
        }
    }
}
