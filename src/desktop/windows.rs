use tauri::{AppHandle, Runtime};

use super::Opened;
use crate::models::SealResponse;
use crate::{Error, Result};

const UNAVAILABLE: &str = "Keeping a secret is not available on this platform yet.";

pub(crate) fn seal<R: Runtime>(
    _app: &AppHandle<R>,
    _identifier: &str,
    _plaintext: &[u8],
) -> Result<SealResponse> {
    Err(Error::Unavailable(UNAVAILABLE.to_string()))
}

pub(crate) fn open<R: Runtime>(
    _app: &AppHandle<R>,
    _identifier: &str,
    _sealed: &str,
) -> Result<Opened> {
    Err(Error::Unavailable(UNAVAILABLE.to_string()))
}

pub(crate) fn delete<R: Runtime>(_app: &AppHandle<R>, _identifier: &str) -> Result<bool> {
    Err(Error::Unavailable(UNAVAILABLE.to_string()))
}
