use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierRequest {
    pub identifier: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateResponse {
    pub message: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExistsResponse {
    pub exists: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPayloadRequest {
    pub payload: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignPayloadResponse {
    pub signature: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignatureRequest {
    pub identifier: String,
    pub payload: String,
    pub signature: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifySignatureResponse {
    pub valid: bool,
}

/// What is holding the key a secret was sealed under.
///
/// `Hardware` is a key that never leaves a secure element, TPM, StrongBox or
/// Secure Enclave. `System` is the operating system's own protected store, bound
/// to this user on this device. `Software` is a key file under the app's data
/// directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backing {
    Hardware,
    System,
    Software,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealRequest {
    pub identifier: String,
    pub plaintext: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealResponse {
    pub sealed: String,
    pub backing: Backing,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequest {
    pub identifier: String,
    pub sealed: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenResponse {
    pub plaintext: String,
    pub backing: Backing,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResponse {
    pub deleted: bool,
}

// The secret never reaches a log: these print everything but it.
impl std::fmt::Debug for SealRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealRequest")
            .field("identifier", &self.identifier)
            .field("plaintext", &"<elided>")
            .finish()
    }
}

impl std::fmt::Debug for OpenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenResponse")
            .field("plaintext", &"<elided>")
            .field("backing", &self.backing)
            .finish()
    }
}
