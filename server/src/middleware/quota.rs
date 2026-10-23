use sqlx::PgPool;
use uuid::Uuid;
use crate::error::{AppError, Result};

pub struct QuotaChecker<'a> {
    db: &'a PgPool,
    org_id: Uuid,
}

impl<'a> QuotaChecker<'a> {
    pub fn new(db: &'a PgPool, org_id: Uuid) -> Self {
        Self { db, org_id }
    }

    pub async fn check_profile_limit(&self) -> Result<()> {
        let row = sqlx::query!(
            r#"
            SELECT
                p.max_profiles,
                COUNT(pr.id) AS current
            FROM orgs o
            JOIN plans p ON p.id = o.plan_id
            LEFT JOIN profiles pr ON pr.org_id = o.id
            WHERE o.id = $1
            GROUP BY p.max_profiles
            "#,
            self.org_id
        )
        .fetch_one(self.db)
        .await?;

        let max = row.max_profiles;
        let current = row.current.unwrap_or(0);

        if max != -1 && current >= max as i64 {
            return Err(AppError::QuotaExceeded(
                format!("profile limit reached ({current}/{max}). upgrade your plan.")
            ));
        }
        Ok(())
    }

    pub async fn check_concurrent_sessions(&self) -> Result<()> {
        let row = sqlx::query!(
            r#"
            SELECT
                p.max_concurrent_sessions,
                COUNT(s.id) AS current
            FROM orgs o
            JOIN plans p ON p.id = o.plan_id
            LEFT JOIN sessions s ON s.org_id = o.id AND s.status = 'running'
            WHERE o.id = $1
            GROUP BY p.max_concurrent_sessions
            "#,
            self.org_id
        )
        .fetch_one(self.db)
        .await?;

        let max = row.max_concurrent_sessions;
        let current = row.current.unwrap_or(0);

        if max != -1 && current >= max as i64 {
            return Err(AppError::QuotaExceeded(
                format!("concurrent session limit reached ({current}/{max}). upgrade your plan.")
            ));
        }
        Ok(())
    }

    pub async fn check_subscription_active(&self) -> Result<()> {
        let row = sqlx::query!(
            "SELECT subscription_status, trial_ends_at FROM orgs WHERE id = $1",
            self.org_id
        )
        .fetch_one(self.db)
        .await?;

        let ok = match row.subscription_status.as_str() {
            "active" => true,
            "trialing" => {
                row.trial_ends_at
                    .map(|t| t > time::OffsetDateTime::now_utc())
                    .unwrap_or(false)
            }
            _ => false,
        };

        if !ok {
            return Err(AppError::Forbidden("subscription inactive or expired".into()));
        }
        Ok(())
    }
}
