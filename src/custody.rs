//! Custody parts are a one-way ownership handoff into a product-owned secret store.

use zeroize::Zeroize;

use crate::AccountProjection;

pub struct CustodyParts {
    id_token: String,
    access_token: String,
    refresh_token: String,
    projection: AccountProjection,
}

impl CustodyParts {
    pub(crate) const fn new(
        id_token: String,
        access_token: String,
        refresh_token: String,
        projection: AccountProjection,
    ) -> Self {
        Self {
            id_token,
            access_token,
            refresh_token,
            projection,
        }
    }

    #[must_use]
    pub const fn projection(&self) -> &AccountProjection {
        &self.projection
    }

    #[must_use]
    pub fn expose_for_custody(mut self) -> (String, String, String, AccountProjection) {
        (
            std::mem::take(&mut self.id_token),
            std::mem::take(&mut self.access_token),
            std::mem::take(&mut self.refresh_token),
            self.projection.clone(),
        )
    }
}

impl Drop for CustodyParts {
    fn drop(&mut self) {
        self.id_token.zeroize();
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
