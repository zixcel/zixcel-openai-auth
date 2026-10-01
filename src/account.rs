//! Account projection is the only authorization result intended for product UI.

use crate::VerifiedClaims;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProjection {
    email: Option<String>,
    plan_type: Option<String>,
    user_id: Option<String>,
    account_id: Option<String>,
    fedramp: bool,
}

impl AccountProjection {
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    #[must_use]
    pub fn plan_type(&self) -> Option<&str> {
        self.plan_type.as_deref()
    }

    #[must_use]
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    #[must_use]
    pub const fn is_fedramp(&self) -> bool {
        self.fedramp
    }

    pub(crate) fn from_claims(claims: VerifiedClaims) -> Self {
        Self {
            email: claims.email,
            plan_type: claims.plan_type,
            user_id: claims.user_id,
            account_id: claims.account_id,
            fedramp: claims.fedramp,
        }
    }

    pub(crate) fn same_identity(&self, claims: &VerifiedClaims) -> bool {
        (self.user_id.is_some() || self.account_id.is_some())
            && Self::claims_have_stable_identity(claims)
            && self
                .user_id
                .as_ref()
                .is_none_or(|value| claims.user_id.as_ref() == Some(value))
            && self
                .account_id
                .as_ref()
                .is_none_or(|value| claims.account_id.as_ref() == Some(value))
    }

    pub(crate) const fn claims_have_stable_identity(claims: &VerifiedClaims) -> bool {
        claims.user_id.is_some() || claims.account_id.is_some()
    }
}
