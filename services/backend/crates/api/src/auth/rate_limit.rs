//! Deneme sınırları (AUT-02, RES-01).
//!
//! Sayaçlar PostgreSQL'de tutulur; bütün API kopyaları aynı sayacı atomik olarak artırır.
//! Sınır aşıldığında hesap kalıcı olarak kilitlenmez: pencere bitince deneme yeniden açılır.
//! Böylece bir saldırgan başkasının hesabını kalıcı olarak kilitleyemez; parola sıfırlama gibi
//! meşru kurtarma yolları ayrı sayaçlarla çalışmaya devam eder.

use sqlx::PgConnection;

use super::codes::rate_key;
use crate::error::{ApiError, ApiResult};

/// Bir sayacın kapsamı, penceresi ve sınırı.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub scope: &'static str,
    pub window_secs: i32,
    pub limit: i32,
}

/// Giriş denemeleri: hesap başına, kaynak (IP) başına ve bütün sistem için.
pub const LOGIN_PER_ACCOUNT: Budget = Budget {
    scope: "login:account",
    window_secs: 15 * 60,
    limit: 10,
};
pub const LOGIN_PER_IP: Budget = Budget {
    scope: "login:ip",
    window_secs: 15 * 60,
    limit: 50,
};
pub const LOGIN_GLOBAL: Budget = Budget {
    scope: "login:global",
    window_secs: 60,
    limit: 3000,
};

/// SMS gönderimi: telefon başına, kaynak başına ve maliyet için bütün sistem.
pub const SMS_PER_PHONE: Budget = Budget {
    scope: "sms:phone",
    window_secs: 15 * 60,
    limit: 3,
};
pub const SMS_PER_IP: Budget = Budget {
    scope: "sms:ip",
    window_secs: 60 * 60,
    limit: 10,
};
pub const SMS_GLOBAL: Budget = Budget {
    scope: "sms:global",
    window_secs: 60 * 60,
    limit: 1000,
};

/// Kod doğrulama denemeleri kaynak başına (kod başına sınır ayrıca veritabanında: 5).
pub const VERIFY_PER_IP: Budget = Budget {
    scope: "verify:ip",
    window_secs: 15 * 60,
    limit: 30,
};

/// Token yenileme kaynak başına.
pub const REFRESH_PER_IP: Budget = Budget {
    scope: "refresh:ip",
    window_secs: 15 * 60,
    limit: 300,
};

/// Sayacı bir artırır; sınır aşıldıysa `TooManyRequests` döner.
pub async fn hit(
    conn: &mut PgConnection,
    hmac_secret: &[u8],
    budget: Budget,
    value: &str,
) -> ApiResult<()> {
    let key = rate_key(hmac_secret, budget.scope, value);
    let (hits, retry_after): (i32, i32) = sqlx::query_as(
        "WITH w AS (
             SELECT to_timestamp(floor(extract(epoch FROM now()) / $2) * $2) AS start
         )
         INSERT INTO rate_limit_buckets (key, window_start, hits)
         SELECT $1, w.start, 1 FROM w
         ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limit_buckets.hits + 1
         RETURNING hits,
                   greatest(1, ceil(extract(epoch FROM window_start) + $2 - extract(epoch FROM now())))::int",
    )
    .bind(key)
    .bind(budget.window_secs)
    .fetch_one(&mut *conn)
    .await?;

    if hits > budget.limit {
        tracing::warn!(scope = budget.scope, "deneme sınırı aşıldı");
        return Err(ApiError::TooManyRequests {
            retry_after_secs: u64::try_from(retry_after).unwrap_or(60),
        });
    }
    Ok(())
}

/// Bir günden eski pencereleri siler. Arka planda düzenli çağrılır.
pub async fn purge_old(conn: &mut PgConnection) -> Result<u64, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM rate_limit_buckets WHERE window_start < now() - interval '1 day'")
            .execute(conn)
            .await?;
    Ok(result.rows_affected())
}

/// Panel komutları kullanıcı başına.
pub const COMMAND_PER_USER: Budget = Budget {
    scope: "command:user",
    window_secs: 60,
    limit: 30,
};

/// Panik butonu kullanıcı başına (kötüye kullanıma karşı; meşru kullanım için geniş).
pub const PANIC_PER_USER: Budget = Budget {
    scope: "panic:user",
    window_secs: 10 * 60,
    limit: 10,
};

/// Davetler (RES-01): bir organizasyonun ve bir kullanıcının gönderebileceği davet sayısı, ve bir
/// numaraya bütün organizasyonlardan gidebilecek davet SMS'i. Davet SMS'i kayıt ve sıfırlama
/// kodlarının sayacını kullanmaz; davetle birinin kod alması engellenemez.
pub const INVITE_PER_ORG: Budget = Budget {
    scope: "invite:org",
    window_secs: 24 * 60 * 60,
    limit: 20,
};
pub const INVITE_PER_USER: Budget = Budget {
    scope: "invite:user",
    window_secs: 60 * 60,
    limit: 10,
};
pub const INVITE_SMS_PER_PHONE: Budget = Budget {
    scope: "invite:phone",
    window_secs: 24 * 60 * 60,
    limit: 3,
};
