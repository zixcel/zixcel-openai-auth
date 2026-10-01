//! Callback material is validated before it can enter a browser attempt.

use zeroize::Zeroize;

use crate::{Result, validation};

pub struct BrowserCallback {
    code: String,
    state: String,
}

impl BrowserCallback {
    /// Validates callback code and state before ownership enters an attempt.
    ///
    /// # Errors
    /// Returns a canonical failure when either callback value is malformed.
    pub fn new(code: String, state: String) -> Result<Self> {
        validation::secret(&code)?;
        if !validation::base64url(&state) {
            return Err(crate::browser_plan::invalid_plan());
        }
        Ok(Self { code, state })
    }

    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    pub(crate) fn state(&self) -> &str {
        &self.state
    }
}

impl Drop for BrowserCallback {
    fn drop(&mut self) {
        self.code.zeroize();
        self.state.zeroize();
    }
}
