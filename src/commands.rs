use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::CryptoExt;
use crate::Result;

#[command]
pub(crate) async fn generate<R: Runtime>(
    app: AppHandle<R>,
    payload: IdentifierRequest,
) -> Result<GenerateResponse> {
    app.crypto().generate(payload)
}

#[command]
pub(crate) async fn exists<R: Runtime>(
    app: AppHandle<R>,
    payload: IdentifierRequest,
) -> Result<ExistsResponse> {
    app.crypto().exists(payload)
}

#[command]
pub(crate) async fn get_public_key<R: Runtime>(
    app: AppHandle<R>,
    payload: IdentifierRequest,
) -> Result<GetPublicKeyResponse> {
    app.crypto().get_public_key(payload)
}

#[command]
pub(crate) async fn sign_payload<R: Runtime>(
    app: AppHandle<R>,
    payload: SignPayloadRequest,
) -> Result<SignPayloadResponse> {
    app.crypto().sign_payload(payload)
}

#[command]
pub(crate) async fn verify_signature<R: Runtime>(
    app: AppHandle<R>,
    payload: VerifySignatureRequest,
) -> Result<VerifySignatureResponse> {
    app.crypto().verify_signature(payload)
}

#[command]
pub(crate) async fn seal<R: Runtime>(
    app: AppHandle<R>,
    payload: SealRequest,
) -> Result<SealResponse> {
    app.crypto().seal(payload)
}

#[command]
pub(crate) async fn open<R: Runtime>(
    app: AppHandle<R>,
    payload: OpenRequest,
) -> Result<OpenResponse> {
    app.crypto().open(payload)
}

#[command]
pub(crate) async fn delete<R: Runtime>(
    app: AppHandle<R>,
    payload: IdentifierRequest,
) -> Result<DeleteResponse> {
    app.crypto().delete(payload)
}
