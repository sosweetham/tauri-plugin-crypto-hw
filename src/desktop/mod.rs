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

impl<R: Runtime> Crypto<R> {
    pub fn generate(&self, payload: IdentifierRequest) -> crate::Result<GenerateResponse> {
        Ok(GenerateResponse {
            message: format!("Generated identifier: {}", payload.identifier),
        })
    }
    pub fn exists(&self, payload: IdentifierRequest) -> crate::Result<ExistsResponse> {
        Ok(ExistsResponse {
            exists: payload.identifier == "exists",
        })
    }
    pub fn get_public_key(
        &self,
        payload: IdentifierRequest,
    ) -> crate::Result<GetPublicKeyResponse> {
        Ok(GetPublicKeyResponse {
            public_key: payload.identifier,
        })
    }
    pub fn sign_payload(&self, payload: SignPayloadRequest) -> crate::Result<SignPayloadResponse> {
        Ok(SignPayloadResponse {
            signature: format!("Signature for {}: {}", payload.identifier, payload.payload),
        })
    }
    pub fn verify_signature(
        &self,
        payload: VerifySignatureRequest,
    ) -> crate::Result<VerifySignatureResponse> {
        Ok(VerifySignatureResponse {
            valid: payload.signature
                == format!("Signature for {}: {}", payload.identifier, payload.payload),
        })
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

