//! Session secrets remain process-local unless moved to an approved custodian.

use zeroize::Zeroize;

use crate::{
    AccountProjection, AuthFailureReason, CustodyParts, Result, VerifiedClaims, error::failure,
    validation::secret,
};

pub struct SessionMaterial {
    id_token: String,
    access_token: String,
    refresh_token: String,
    projection: AccountProjection,
}

impl SessionMaterial {
    pub(crate) fn create(
        id_token: String,
        access_token: String,
        refresh_token: String,
        claims: VerifiedClaims,
    ) -> Result<Self> {
        secret(&id_token)?;
        secret(&access_token)?;
        secret(&refresh_token)?;
        if !AccountProjection::claims_have_stable_identity(&claims) {
            return Err(failure(
                AuthFailureReason::ClaimsBindingMismatch,
                false,
                "managed session has no stable account identifier",
            ));
        }
        Ok(Self {
            id_token,
            access_token,
            refresh_token,
            projection: AccountProjection::from_claims(claims),
        })
    }

    #[must_use]
    pub const fn projection(&self) -> &AccountProjection {
        &self.projection
    }

    #[must_use]
    pub fn access_token_for_request(&self) -> &str {
        &self.access_token
    }

    #[must_use]
    pub fn into_custody_parts(mut self) -> CustodyParts {
        CustodyParts::new(
            std::mem::take(&mut self.id_token),
            std::mem::take(&mut self.access_token),
            std::mem::take(&mut self.refresh_token),
            self.projection.clone(),
        )
    }

    pub(crate) fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    pub(crate) fn commit_refresh(
        &mut self,
        mut access_token: Option<String>,
        mut refresh_token: Option<String>,
        mut identity: Option<(String, VerifiedClaims)>,
    ) -> Result<()> {
        if let Some(value) = access_token.as_deref() {
            secret(value)?;
        }
        if let Some(value) = refresh_token.as_deref() {
            secret(value)?;
        }
        if let Some((id_token, claims)) = identity.as_ref() {
            secret(id_token)?;
            if !self.projection.same_identity(claims) {
                if let Some(value) = &mut access_token {
                    value.zeroize();
                }
                if let Some(value) = &mut refresh_token {
                    value.zeroize();
                }
                if let Some((value, _)) = &mut identity {
                    value.zeroize();
                }
                return Err(failure(
                    AuthFailureReason::ClaimsBindingMismatch,
                    false,
                    "refreshed identity does not match the active session",
                ));
            }
        }
        if let Some(value) = access_token {
            self.access_token.zeroize();
            self.access_token = value;
        }
        if let Some(value) = refresh_token {
            self.refresh_token.zeroize();
            self.refresh_token = value;
        }
        if let Some((id_token, claims)) = identity {
            self.id_token.zeroize();
            self.id_token = id_token;
            self.projection = AccountProjection::from_claims(claims);
        }
        Ok(())
    }
}

impl Drop for SessionMaterial {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
