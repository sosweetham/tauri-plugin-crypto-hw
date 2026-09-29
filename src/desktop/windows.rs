use std::ffi::c_void;

use tauri::{AppHandle, Runtime};
use windows::core::{Owned, HSTRING, PCWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL, NTE_BAD_KEYSET};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey,
    NCryptEncrypt, NCryptFinalizeKey, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC,
    CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG,
};
use zeroize::{Zeroize, Zeroizing};

use super::Opened;
use crate::models::{Backing, SealResponse};
use crate::sealed;
use crate::{Error, Result};

const PLATFORM_SCHEME: &str = "rsa-oaep-tpm";
const DPAPI_SCHEME: &str = "dpapi";

const KEY_BITS: u32 = 2048;

/// RSA-2048 under OAEP with SHA-256 holds the modulus less two hash lengths and
/// two bytes, and there is no second block for the rest to go in.
const MOST_A_PLATFORM_KEY_HOLDS: usize = KEY_BITS as usize / 8 - 2 * 32 - 2;

const NO_SECRET: &str = "There is no secret kept under that name on this device.";
const NOT_KEPT: &str = "That secret could not be kept on this device. Try again.";
const UNREADABLE: &str = "That secret could not be opened. Seal it again.";
const NOT_REMOVED: &str = "That secret could not be removed. Try again.";

/// Which of this platform's two ways holds the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rung {
    Platform,
    Dpapi,
}

/// A key and the provider it came from. The key is freed first: it is the
/// provider's child.
struct PlatformKey {
    key: Owned<NCRYPT_KEY_HANDLE>,
    _provider: Owned<NCRYPT_PROV_HANDLE>,
}

/// The rung a `seal` lands on, holding the key where that rung has one.
enum Keeper {
    Platform(PlatformKey),
    Dpapi,
}

pub(crate) fn seal<R: Runtime>(
    _app: &AppHandle<R>,
    identifier: &str,
    plaintext: &[u8],
) -> Result<SealResponse> {
    match keeper(platform_key(identifier), plaintext.len()) {
        Keeper::Platform(held) => Ok(SealResponse {
            sealed: sealed::format(PLATFORM_SCHEME, &encrypt(&held, plaintext)?),
            backing: Backing::Hardware,
        }),
        Keeper::Dpapi => Ok(SealResponse {
            sealed: sealed::format(DPAPI_SCHEME, &protect(identifier, plaintext)?),
            backing: Backing::System,
        }),
    }
}

pub(crate) fn open<R: Runtime>(
    _app: &AppHandle<R>,
    identifier: &str,
    sealed_text: &str,
) -> Result<Opened> {
    let parsed = sealed::parse(sealed_text)?;
    match rung_for(&parsed.scheme)? {
        // Opening never makes a key: a name this machine has none for is a
        // secret it was not asked to keep, not a fresh one to start.
        Rung::Platform => {
            let provider = provider().ok_or_else(|| Error::Crypto(sealed::FOREIGN.to_string()))?;
            let key = open_key(&provider, &key_name(identifier))
                .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?
                .ok_or_else(|| Error::NotFound(NO_SECRET.to_string()))?;
            let held = PlatformKey {
                key,
                _provider: provider,
            };
            Ok(Opened {
                plaintext: decrypt(&held, &parsed.bytes)?,
                backing: Backing::Hardware,
            })
        }
        Rung::Dpapi => Ok(Opened {
            plaintext: unprotect(identifier, &parsed.bytes)?,
            backing: Backing::System,
        }),
    }
}

/// Only the platform rung persists anything, so an identifier whose secret went
/// to DPAPI has nothing here to remove. The signing key a person generates
/// under the same name is a key of its own and is left alone.
pub(crate) fn delete<R: Runtime>(_app: &AppHandle<R>, identifier: &str) -> Result<bool> {
    let Some(provider) = provider() else {
        return Ok(false);
    };
    let Ok(Some(key)) = open_key(&provider, &key_name(identifier)) else {
        return Ok(false);
    };

    // NCryptDeleteKey frees the handle it is given, so ownership ends here.
    let handle = *key;
    std::mem::forget(key);
    unsafe { NCryptDeleteKey(handle, 0) }.map_err(|_| Error::Crypto(NOT_REMOVED.to_string()))?;
    Ok(true)
}

fn rung_for(scheme: &str) -> Result<Rung> {
    match scheme {
        PLATFORM_SCHEME => Ok(Rung::Platform),
        DPAPI_SCHEME => Ok(Rung::Dpapi),
        _ => Err(Error::Crypto(sealed::FOREIGN.to_string())),
    }
}

/// A secret too long for one RSA block is kept by Windows instead of refused;
/// `backing` says which way it went.
fn keeper(key: Option<PlatformKey>, plaintext_len: usize) -> Keeper {
    match key {
        Some(key) if plaintext_len <= MOST_A_PLATFORM_KEY_HOLDS => Keeper::Platform(key),
        _ => Keeper::Dpapi,
    }
}

/// `None` is a machine whose TPM will not give us this key, which is the whole
/// reason there is a second rung.
fn platform_key(identifier: &str) -> Option<PlatformKey> {
    let provider = provider()?;
    let name = key_name(identifier);
    let key = match open_key(&provider, &name) {
        Ok(Some(key)) => key,
        Ok(None) => create_key(&provider, &name).ok()?,
        Err(_) => return None,
    };
    Some(PlatformKey {
        key,
        _provider: provider,
    })
}

fn provider() -> Option<Owned<NCRYPT_PROV_HANDLE>> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.ok()?;
    Some(unsafe { Owned::new(provider) })
}

/// The sealing key is its own key, kept apart from the signing key the same
/// identifier names.
fn key_name(identifier: &str) -> HSTRING {
    HSTRING::from(std::format!("crypto-hw/{identifier}/seal"))
}

fn open_key(
    provider: &NCRYPT_PROV_HANDLE,
    name: &HSTRING,
) -> windows::core::Result<Option<Owned<NCRYPT_KEY_HANDLE>>> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    match unsafe {
        NCryptOpenKey(
            *provider,
            &mut key,
            name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    } {
        Ok(()) => Ok(Some(unsafe { Owned::new(key) })),
        Err(trouble) if trouble.code() == NTE_BAD_KEYSET => Ok(None),
        Err(trouble) => Err(trouble),
    }
}

/// Sealing must not raise a dialog nobody asked for, so a key that would insist
/// on one fails here and the caller falls to the next rung.
fn create_key(
    provider: &NCRYPT_PROV_HANDLE,
    name: &HSTRING,
) -> windows::core::Result<Owned<NCRYPT_KEY_HANDLE>> {
    let mut key = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            *provider,
            &mut key,
            BCRYPT_RSA_ALGORITHM,
            name,
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    }?;
    let key = unsafe { Owned::new(key) };

    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE::from(*key),
            NCRYPT_LENGTH_PROPERTY,
            &KEY_BITS.to_ne_bytes(),
            NCRYPT_SILENT_FLAG,
        )
    }?;
    unsafe { NCryptFinalizeKey(*key, NCRYPT_SILENT_FLAG) }?;
    Ok(key)
}

fn encrypt(held: &PlatformKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let padding = oaep_sha256();
    let padding = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;

    let mut room = 0u32;
    unsafe {
        NCryptEncrypt(
            *held.key,
            Some(plaintext),
            Some(padding),
            None,
            &mut room,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|_| Error::Crypto(NOT_KEPT.to_string()))?;

    let mut ciphertext = vec![0u8; room as usize];
    unsafe {
        NCryptEncrypt(
            *held.key,
            Some(plaintext),
            Some(padding),
            Some(ciphertext.as_mut_slice()),
            &mut room,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|_| Error::Crypto(NOT_KEPT.to_string()))?;
    ciphertext.truncate(room as usize);
    Ok(ciphertext)
}

fn decrypt(held: &PlatformKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let padding = oaep_sha256();
    let padding = &padding as *const BCRYPT_OAEP_PADDING_INFO as *const c_void;

    let mut room = 0u32;
    unsafe {
        NCryptDecrypt(
            *held.key,
            Some(ciphertext),
            Some(padding),
            None,
            &mut room,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

    let mut plaintext = Zeroizing::new(vec![0u8; room as usize]);
    unsafe {
        NCryptDecrypt(
            *held.key,
            Some(ciphertext),
            Some(padding),
            Some(plaintext.as_mut_slice()),
            &mut room,
            NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

    // The sizing call answers with room for a block, not with the length of
    // what comes out of it, so the tail is wiped rather than merely dropped.
    let kept = room as usize;
    plaintext[kept..].zeroize();
    plaintext.truncate(kept);
    Ok(plaintext)
}

fn oaep_sha256() -> BCRYPT_OAEP_PADDING_INFO {
    BCRYPT_OAEP_PADDING_INFO {
        pszAlgId: BCRYPT_SHA256_ALGORITHM,
        pbLabel: std::ptr::null_mut(),
        cbLabel: 0,
    }
}

/// The identifier is mixed into the blob, so a secret kept under one name
/// cannot be opened under another.
fn protect(identifier: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let salt = identifier.as_bytes();
    let mut entropy = CRYPT_INTEGER_BLOB {
        cbData: salt.len() as u32,
        pbData: salt.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|_| Error::Crypto(NOT_KEPT.to_string()))?;

    let written = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe { LocalFree(Some(HLOCAL(out.pbData as *mut c_void))) };
    Ok(written)
}

fn unprotect(identifier: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let salt = identifier.as_bytes();
    let mut entropy = CRYPT_INTEGER_BLOB {
        cbData: salt.len() as u32,
        pbData: salt.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&mut entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .map_err(|_| Error::Crypto(sealed::FOREIGN.to_string()))?;

    let held = unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) };
    let plaintext = Zeroizing::new(held.to_vec());
    // This buffer belongs to the system, and it is holding the secret.
    held.zeroize();
    unsafe { LocalFree(Some(HLOCAL(out.pbData as *mut c_void))) };
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A null handle's free is a no-op, so this stands in for a key without
    /// asking the machine for one.
    fn stub_key() -> PlatformKey {
        PlatformKey {
            key: unsafe { Owned::new(NCRYPT_KEY_HANDLE::default()) },
            _provider: unsafe { Owned::new(NCRYPT_PROV_HANDLE::default()) },
        }
    }

    #[test]
    fn reads_the_rung_out_of_the_scheme() {
        assert_eq!(rung_for(PLATFORM_SCHEME).unwrap(), Rung::Platform);
        assert_eq!(rung_for(DPAPI_SCHEME).unwrap(), Rung::Dpapi);
    }

    #[test]
    fn refuses_a_scheme_this_platform_never_writes() {
        for scheme in ["ecies-p256", "aes-gcm-keystore", "aes-gcm-secretservice"] {
            let trouble = rung_for(scheme).unwrap_err();
            assert_eq!(trouble.to_string(), sealed::FOREIGN, "{scheme}");
        }
    }

    #[test]
    fn keeps_a_secret_in_the_platform_key_when_there_is_one() {
        assert!(matches!(keeper(Some(stub_key()), 1), Keeper::Platform(_)));
        assert!(matches!(
            keeper(Some(stub_key()), MOST_A_PLATFORM_KEY_HOLDS),
            Keeper::Platform(_)
        ));
    }

    #[test]
    fn falls_to_windows_with_no_platform_key() {
        assert!(matches!(keeper(None, 1), Keeper::Dpapi));
    }

    #[test]
    fn falls_to_windows_for_a_secret_no_block_would_hold() {
        assert!(matches!(
            keeper(Some(stub_key()), MOST_A_PLATFORM_KEY_HOLDS + 1),
            Keeper::Dpapi
        ));
    }

    #[test]
    fn names_the_sealing_key_apart_from_the_signing_key() {
        assert_eq!(key_name("notes").to_string(), "crypto-hw/notes/seal");
    }
}
