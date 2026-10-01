use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};
use zeroize::Zeroizing;

use crate::models::*;

// Any platform module may call this as its last rung; on a desktop platform with
// no module of its own it is the whole backend.
#[allow(dead_code)]
mod software;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod backend;
#[cfg(windows)]
#[path = "windows.rs"]
mod backend;
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod backend;
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
use software as backend;

/// What a backend hands back from `open`: the bytes, and the rung that held the key.
pub(crate) struct Opened {
    pub plaintext: Zeroizing<Vec<u8>>,
    pub backing: Backing,
}

impl std::fmt::Debug for Opened {
    /// An opened secret must not reach a log, so the plaintext is left out.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("backing", &self.backing)
            .finish_non_exhaustive()
    }
}

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<Crypto<R>> {
    Ok(Crypto(app.clone()))
}

/// Access to the crypto APIs.
pub struct Crypto<R: Runtime>(AppHandle<R>);

/// Said to anybody asking a desktop to sign. A signing key here would be a
/// different key in a different store from the one a phone holds, so there is
/// nothing to answer with and nothing a caller could do to make there be.
const NO_SIGNING: &str = "Signing keys are kept on phones and tablets, not on this device.";

fn unsigned<T>() -> crate::Result<T> {
    Err(crate::Error::Unavailable(NO_SIGNING.to_string()))
}

impl<R: Runtime> Crypto<R> {
    pub fn generate(&self, _payload: IdentifierRequest) -> crate::Result<GenerateResponse> {
        unsigned()
    }
    pub fn exists(&self, _payload: IdentifierRequest) -> crate::Result<ExistsResponse> {
        unsigned()
    }
    pub fn get_public_key(
        &self,
        _payload: IdentifierRequest,
    ) -> crate::Result<GetPublicKeyResponse> {
        unsigned()
    }
    pub fn sign_payload(&self, _payload: SignPayloadRequest) -> crate::Result<SignPayloadResponse> {
        unsigned()
    }
    pub fn verify_signature(
        &self,
        _payload: VerifySignatureRequest,
    ) -> crate::Result<VerifySignatureResponse> {
        unsigned()
    }

    pub fn seal(&self, payload: SealRequest) -> crate::Result<SealResponse> {
        let plaintext = Zeroizing::new(payload.plaintext.into_bytes());
        backend::seal(&self.0, &payload.identifier, &plaintext)
    }

    pub fn open(&self, payload: OpenRequest) -> crate::Result<OpenResponse> {
        let opened = backend::open(&self.0, &payload.identifier, &payload.sealed)?;
        let plaintext = String::from_utf8(opened.plaintext.to_vec())
            .map_err(|_| crate::Error::Crypto("That secret is not text.".to_string()))?;
        Ok(OpenResponse {
            plaintext,
            backing: opened.backing,
        })
    }

    pub fn delete(&self, payload: IdentifierRequest) -> crate::Result<DeleteResponse> {
        Ok(DeleteResponse {
            deleted: backend::delete(&self.0, &payload.identifier)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A desktop answering a signing call with something that looks like a
    /// signature is worse than one that cannot sign: a caller believes it.
    #[test]
    fn a_desktop_refuses_to_sign_rather_than_answering_with_anything() {
        let said = |e: crate::Error| e.to_string();

        assert_eq!(
            said(unsigned::<GenerateResponse>().unwrap_err()),
            NO_SIGNING
        );
        assert_eq!(said(unsigned::<ExistsResponse>().unwrap_err()), NO_SIGNING);
        assert_eq!(
            said(unsigned::<GetPublicKeyResponse>().unwrap_err()),
            NO_SIGNING
        );
        assert_eq!(
            said(unsigned::<SignPayloadResponse>().unwrap_err()),
            NO_SIGNING
        );
        assert_eq!(
            said(unsigned::<VerifySignatureResponse>().unwrap_err()),
            NO_SIGNING
        );
    }

    #[test]
    fn what_a_desktop_cannot_do_is_told_apart_from_what_went_wrong() {
        assert!(matches!(
            unsigned::<ExistsResponse>().unwrap_err(),
            crate::Error::Unavailable(_)
        ));
    }
}
