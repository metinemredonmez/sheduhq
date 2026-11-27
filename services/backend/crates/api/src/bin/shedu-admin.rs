//! `shedu-admin`: platform yöneticisi aracı (pilot). Yalnızca sunucuda, kendi veritabanı rolüyle
//! (`shedu_admin`) çalışır; API'den erişilemez (AZ-05, OPS-02).
//!
//! Ortam: `DATABASE_URL` (zorunlu; üretimde `sslmode=verify-full` veya `require`),
//! `SHEDU_ENV` (`development` değilse üretim sayılır), `SHEDU_ADMIN_DB_ROLE` (varsayılan
//! `shedu_admin`). İşlemi yapan kişi `--operator` ile ya da sunucudaki `USER` değişkeninden
//! alınır; her değişiklik `--reason` ister ve denetim kaydına yazılır.
//!
//! Örnekler:
//!   shedu-admin org list
//!   shedu-admin org show <ORG_ID>
//!   shedu-admin org create --name "Örnek AŞ" --kind business --owner-phone +905551112233 \
//!       --owner-name "Ayşe Yılmaz" --reason "Pilot müşteri kurulumu, sözleşme 2026/14"
//!   shedu-admin panel add --org <ORG_ID> --name "Merkez" --brand acme --serial SN-1 \
//!       --layout panel.json --reason "Pilot panel montajı"
//!   shedu-admin user disable --phone +905551112233 --reason "Cihaz çalındı bildirimi"
//!   shedu-admin flag set camera_live --state on --rollout 0 --description "Canlı kamera" \
//!       --reason "Pilotta denenecek"
//!   shedu-admin flag override camera_live --org <ORG_ID> --state on --reason "Pilot müşteri"

use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use shedu_api::{
    admin::{self, ADMIN_ROLE, FlagChange, NewOrganization, NewPanel, Operator, PanelLayout},
    db,
    sms::mask_phone,
};
use sqlx::postgres::PgConnectOptions;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(
    name = "shedu-admin",
    version,
    about = "Shedu platform yöneticisi aracı"
)]
struct Cli {
    /// İşlemi yapan kişi (varsayılan: sunucudaki kullanıcı adı).
    #[arg(long, env = "USER", global = true, hide_env_values = true)]
    operator: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Organizasyonlar.
    #[command(subcommand)]
    Org(OrgCommand),
    /// Paneller.
    #[command(subcommand)]
    Panel(PanelCommand),
    /// Kullanıcılar.
    #[command(subcommand)]
    User(UserCommand),
    /// Özellik bayrakları.
    #[command(subcommand)]
    Flag(FlagCommand),
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum OnOff {
    On,
    Off,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum OverrideState {
    On,
    Off,
    /// Organizasyon ayarını kaldırır; genel kural uygulanır.
    Clear,
}

#[derive(Subcommand, Debug)]
enum FlagCommand {
    /// Bütün bayraklar ve organizasyon ayarları.
    List,
    /// Bayrağı oluşturur veya değiştirir. `off` her organizasyonda kapatır (acil kapatma).
    Set {
        key: String,
        #[arg(long, value_enum)]
        state: OnOff,
        /// Açık bayrağın uygulanacağı organizasyon yüzdesi (0–100). Yeni bayrakta varsayılan 100.
        #[arg(long)]
        rollout: Option<i16>,
        /// Yeni bayrakta zorunlu.
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        reason: String,
    },
    /// Bir organizasyon için bayrağı açar, kapatır veya ayarı kaldırır.
    Override {
        key: String,
        #[arg(long)]
        org: Uuid,
        #[arg(long, value_enum)]
        state: OverrideState,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum OrgCommand {
    /// Bütün organizasyonların özeti.
    List,
    /// Bir organizasyonun üyeleri ve panelleri.
    Show { id: Uuid },
    /// Yeni organizasyon ve sahibi. Sahip yeni bir kullanıcıysa parolasını "parola sıfırlama"
    /// akışıyla (SMS kodu) kendisi belirler.
    Create {
        #[arg(long)]
        name: String,
        /// home, business veya monitoring_center.
        #[arg(long)]
        kind: String,
        #[arg(long)]
        owner_phone: String,
        /// Sahip yeni bir kullanıcıysa görünen adı.
        #[arg(long, default_value = "")]
        owner_name: String,
        /// Gerekçe (10–300 karakter); denetim kaydına yazılır.
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum PanelCommand {
    /// Gerçek bir paneli organizasyona atar; bölüm ve zon düzeni JSON dosyasından okunur.
    Add {
        #[arg(long)]
        org: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        brand: String,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        serial: String,
        /// {"partitions":[{"number":1,"name":"Ev"}],"zones":[{"number":1,"name":"Kapı","kind":"intrusion","partitions":[1]}]}
        #[arg(long)]
        layout: PathBuf,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand, Debug)]
enum UserCommand {
    /// Kullanıcıyı kapatır: bütün oturumları ve bildirimleri hemen biter.
    Disable {
        #[arg(long)]
        phone: String,
        #[arg(long)]
        reason: String,
    },
    /// Kapatılmış kullanıcıyı yeniden açar.
    Enable {
        #[arg(long)]
        phone: String,
        #[arg(long)]
        reason: String,
    },
}

/// Dosya boyutu sınırı: düzen dosyası küçük olmalı.
const MAX_LAYOUT_BYTES: u64 = 1024 * 1024;

fn operator(cli: &Cli, reason: &str) -> Result<Operator, String> {
    let name = cli.operator.as_deref().unwrap_or_default();
    Operator::new(name, reason).map_err(|e| e.to_string())
}

fn database() -> Result<(PgConnectOptions, String), String> {
    let url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL tanımlı değil".to_owned())?;
    let development = std::env::var("SHEDU_ENV").as_deref() == Ok("development");
    if !development && !(url.contains("sslmode=verify-full") || url.contains("sslmode=require")) {
        return Err("üretimde DATABASE_URL sslmode=verify-full (veya require) içermeli".to_owned());
    }
    let role = std::env::var("SHEDU_ADMIN_DB_ROLE").unwrap_or_else(|_| ADMIN_ROLE.to_owned());
    let options = url
        .parse::<PgConnectOptions>()
        .map_err(|_| "DATABASE_URL geçersiz".to_owned())?;
    Ok((options, role))
}

async fn run(cli: Cli) -> Result<(), String> {
    let (options, role) = database()?;
    let pool = db::pool_options(Some(role))
        .max_connections(2)
        .connect_with(options)
        .await
        .map_err(|e| format!("veritabanına bağlanılamadı: {e}"))?;
    let error = |e: admin::AdminError| e.to_string();

    match &cli.command {
        Command::Org(OrgCommand::List) => {
            for org in admin::list_organizations(&pool).await.map_err(error)? {
                println!(
                    "{}  {:<18} üye {:>3}  panel {:>3}  {}",
                    org.id, org.kind, org.members, org.panels, org.name
                );
            }
        }
        Command::Org(OrgCommand::Show { id }) => {
            let (org, members, panels) =
                admin::show_organization(&pool, *id).await.map_err(error)?;
            println!("{} ({}) — {}", org.name, org.kind, org.id);
            println!("Üyeler:");
            for m in members {
                let phone = m.phone.as_deref().map(mask_phone).unwrap_or_default();
                println!(
                    "  {:<8} {}  {}  {}",
                    m.role, m.user_id, phone, m.display_name
                );
            }
            println!("Paneller:");
            for p in panels {
                println!(
                    "  {}  {} {} ({})  bölüm {}  zon {}  {}",
                    p.id, p.brand, p.device_serial, p.connectivity, p.partitions, p.zones, p.name
                );
            }
        }
        Command::Org(OrgCommand::Create {
            name,
            kind,
            owner_phone,
            owner_name,
            reason,
        }) => {
            let operator = operator(&cli, reason)?;
            let created = admin::create_organization(
                &pool,
                &operator,
                NewOrganization {
                    name,
                    kind,
                    owner_phone,
                    owner_name,
                },
            )
            .await
            .map_err(error)?;
            println!("organizasyon: {}", created.organization_id);
            println!(
                "sahip: {} ({})",
                created.owner_user_id,
                if created.owner_created {
                    "yeni hesap; parolasını uygulamadaki parola sıfırlama ile belirleyecek"
                } else {
                    "mevcut hesap"
                }
            );
        }
        Command::Panel(PanelCommand::Add {
            org,
            name,
            brand,
            model,
            serial,
            layout,
            reason,
        }) => {
            let operator = operator(&cli, reason)?;
            let size = fs::metadata(layout)
                .map_err(|e| format!("düzen dosyası okunamadı: {e}"))?
                .len();
            if size > MAX_LAYOUT_BYTES {
                return Err("düzen dosyası çok büyük".to_owned());
            }
            let raw =
                fs::read_to_string(layout).map_err(|e| format!("düzen dosyası okunamadı: {e}"))?;
            let layout: PanelLayout =
                serde_json::from_str(&raw).map_err(|e| format!("düzen dosyası geçersiz: {e}"))?;
            let panel_id = admin::add_panel(
                &pool,
                &operator,
                NewPanel {
                    organization_id: *org,
                    name,
                    brand,
                    model: model.as_deref(),
                    device_serial: serial,
                    layout: &layout,
                },
            )
            .await
            .map_err(error)?;
            println!("panel: {panel_id} (çevrimdışı başlar; gateway bağlanınca çevrimiçi olur)");
        }
        Command::User(UserCommand::Disable { phone, reason }) => {
            let operator = operator(&cli, reason)?;
            let id = admin::set_user_active(&pool, &operator, phone, false)
                .await
                .map_err(error)?;
            println!("kapatıldı: {id} (oturumlar ve bildirimler iptal edildi)");
        }
        Command::Flag(FlagCommand::List) => {
            let (flags, overrides) = admin::list_flags(&pool).await.map_err(error)?;
            for f in flags {
                println!(
                    "{:<28} {:<4} %{:>3}  {}",
                    f.key,
                    if f.enabled { "açık" } else { "kapalı" },
                    f.rollout_percent,
                    f.description
                );
                for o in overrides.iter().filter(|o| o.flag_key == f.key) {
                    println!(
                        "    {}  {}",
                        o.organization_id,
                        if o.enabled { "açık" } else { "kapalı" }
                    );
                }
            }
        }
        Command::Flag(FlagCommand::Set {
            key,
            state,
            rollout,
            description,
            reason,
        }) => {
            let operator = operator(&cli, reason)?;
            let created = admin::set_flag(
                &pool,
                &operator,
                FlagChange {
                    key,
                    description: description.as_deref(),
                    enabled: matches!(state, OnOff::On),
                    rollout_percent: *rollout,
                },
            )
            .await
            .map_err(error)?;
            println!(
                "{key}: {}",
                if created {
                    "oluşturuldu"
                } else {
                    "güncellendi"
                }
            );
        }
        Command::Flag(FlagCommand::Override {
            key,
            org,
            state,
            reason,
        }) => {
            let operator = operator(&cli, reason)?;
            let value = match state {
                OverrideState::On => Some(true),
                OverrideState::Off => Some(false),
                OverrideState::Clear => None,
            };
            admin::set_flag_override(&pool, &operator, key, *org, value)
                .await
                .map_err(error)?;
            println!("{key} @ {org}: {state:?}");
        }
        Command::User(UserCommand::Enable { phone, reason }) => {
            let operator = operator(&cli, reason)?;
            let id = admin::set_user_active(&pool, &operator, phone, true)
                .await
                .map_err(error)?;
            println!("açıldı: {id}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("hata: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_require_a_reason() {
        assert!(
            Cli::try_parse_from(["shedu-admin", "user", "disable", "--phone", "+905551112233"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "shedu-admin",
                "org",
                "create",
                "--name",
                "X",
                "--kind",
                "business",
                "--owner-phone",
                "+905551112233"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["shedu-admin", "org", "list"]).is_ok());
    }

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
