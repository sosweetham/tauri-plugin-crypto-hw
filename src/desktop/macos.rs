//! Sealing on macOS. README.md § backing says what each rung reports.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use rand::rngs::OsRng;
use rand::RngCore;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, SecKey};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password, AccessControlOptions,
};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess, SecKeyRef};
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecClass,
    kSecClassKey, kSecPrivateKeyAttrs, kSecReturnRef,
};
use security_framework_sys::key::SecKeyCreateRandomKey;
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};
use tauri::{AppHandle, Runtime};
use zeroize::Zeroizing;

use super::software;
use super::Opened;
use crate::models::{Backing, SealResponse};
use crate::sealed;
use crate::{Error, Result};

// Security.framework globals that security-framework-sys does not re-export.
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecAttrApplicationTag: CFStringRef;
    static kSecUseDataProtectionKeychain: CFStringRef;
}

const ENCLAVE_SCHEME: &str = "ecies-p256";

/// The plugin's scheme set has no name for a Mac keychain rung, so this rung
/// writes the one it reserves for the operating system's own secret store.
const KEYCHAIN_SCHEME: &str = "aes-gcm-secretservice";

const NO_SECRET: &str = "There is no secret kept under that name on this device.";
const UNREADABLE: &str = "That secret could not be opened. Seal it again.";
const DAMAGED_KEY: &str =
    "The key for that secret is damaged. Delete it and seal the secret again.";
const NO_STORE: &str = "This Mac would not let the app keep or read that secret. Try again.";
const NO_ENCLAVE: &str = "This Mac has no secure chip to keep that secret in.";

/// Where a sealing key can live, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rung {
    Enclave,
    Keychain,
    KeyFile,
}

const LADDER: [Rung; 3] = [Rung::Enclave, Rung::Keychain, Rung::KeyFile];

pub(crate) fn seal<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    plaintext: &[u8],
) -> Result<SealResponse> {
    let tag = seal_tag(app, identifier);
    descend(|rung| match rung {
        Rung::Enclave => enclave::seal(&tag, plaintext),
        Rung::Keychain => keychain::seal(&tag, plaintext),
        Rung::KeyFile => software::seal(app, identifier, plaintext),
    })
}

pub(crate) fn open<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    sealed_text: &str,
) -> Result<Opened> {
    let parsed = sealed::parse(sealed_text)?;
    match rung_that_wrote(&parsed.scheme) {
        Some(Rung::Enclave) => enclave::open(&seal_tag(app, identifier), &parsed.bytes),
        Some(Rung::Keychain) => keychain::open(&seal_tag(app, identifier), &parsed.bytes),
        Some(Rung::KeyFile) => software::open(app, identifier, sealed_text),
        None => Err(Error::Crypto(sealed::FOREIGN.to_string())),
    }
}

pub(crate) fn delete<R: Runtime>(app: &AppHandle<R>, identifier: &str) -> Result<bool> {
    let tag = seal_tag(app, identifier);
    sweep(|rung| match rung {
        Rung::Enclave => enclave::delete(&tag),
        Rung::Keychain => keychain::delete(&tag),
        Rung::KeyFile => software::delete(app, identifier),
    })
}

/// Takes the first rung that answers, and reports the last refusal if none does.
fn descend<T>(mut attempt: impl FnMut(Rung) -> Result<T>) -> Result<T> {
    let mut refusal = None;
    for rung in LADDER {
        match attempt(rung) {
            Ok(answer) => return Ok(answer),
            Err(why) => refusal = Some(why),
        }
    }
    Err(refusal.unwrap_or_else(|| Error::Unavailable(NO_STORE.to_string())))
}

/// Clears every rung, because a secret sealed on a low rung outlives a refusal
/// from a high one: an app that cannot reach the Secure Enclave at all is
/// exactly the app whose secret is on the keychain rung below it. A store this
/// app was never allowed to reach answers that it had nothing, so what is left
/// is a store that refused — and saying a secret is gone while it is still
/// there is the one answer this must never give.
fn sweep(mut clear: impl FnMut(Rung) -> Result<bool>) -> Result<bool> {
    let mut removed = false;
    let mut refusal = None;
    for rung in LADDER {
        match clear(rung) {
            Ok(gone) => removed |= gone,
            Err(why) => refusal = Some(why),
        }
    }
    match refusal {
        Some(why) => Err(why),
        None => Ok(removed),
    }
}

fn rung_that_wrote(scheme: &str) -> Option<Rung> {
    match scheme {
        ENCLAVE_SCHEME => Some(Rung::Enclave),
        KEYCHAIN_SCHEME => Some(Rung::Keychain),
        software::SCHEME => Some(Rung::KeyFile),
        _ => None,
    }
}

/// Names the sealing key apart from the signing key of the same identifier.
fn seal_tag<R: Runtime>(app: &AppHandle<R>, identifier: &str) -> String {
    std::format!("{}.{identifier}.seal", app.config().identifier)
}

fn attr(name: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(name) }
}

fn attr_value(value: CFStringRef) -> CFType {
    attr(value).into_CFType()
}

mod enclave {
    use super::*;

    const ECIES: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

    pub(super) fn seal(tag: &str, plaintext: &[u8]) -> Result<SealResponse> {
        let private = match find(tag)? {
            Some(key) => key,
            None => create(tag)?,
        };
        let public = private
            .public_key()
            .ok_or_else(|| Error::Unavailable(NO_ENCLAVE.to_string()))?;
        let payload = public
            .encrypt_data(ECIES, plaintext)
            .map_err(|_| Error::Unavailable(NO_ENCLAVE.to_string()))?;

        Ok(SealResponse {
            sealed: sealed::format(ENCLAVE_SCHEME, &payload),
            backing: Backing::Hardware,
        })
    }

    pub(super) fn open(tag: &str, payload: &[u8]) -> Result<Opened> {
        let private = find(tag)?.ok_or_else(|| Error::NotFound(NO_SECRET.to_string()))?;
        let plaintext = private
            .decrypt_data(ECIES, payload)
            .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

        Ok(Opened {
            plaintext: Zeroizing::new(plaintext),
            backing: Backing::Hardware,
        })
    }

    /// `errSecMissingEntitlement` (SecBase.h): this process is not allowed to
    /// reach the data-protection keychain, so it never put a key there and
    /// there is nothing of ours to remove.
    const NEVER_ALLOWED: i32 = -34018;

    pub(super) fn delete(tag: &str) -> Result<bool> {
        let query = query(tag, false);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status == errSecSuccess {
            Ok(true)
        } else if status == errSecItemNotFound || status == NEVER_ALLOWED {
            Ok(false)
        } else {
            Err(Error::Unavailable(NO_STORE.to_string()))
        }
    }

    fn find(tag: &str) -> Result<Option<SecKey>> {
        let query = query(tag, true);
        let mut found: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut found) };

        if status == errSecItemNotFound {
            return Ok(None);
        }
        if status != errSecSuccess || found.is_null() {
            return Err(Error::Unavailable(NO_ENCLAVE.to_string()));
        }
        Ok(Some(unsafe {
            SecKey::wrap_under_create_rule(found as SecKeyRef)
        }))
    }

    fn create(tag: &str) -> Result<SecKey> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
        )
        .map_err(|_| Error::Unavailable(NO_ENCLAVE.to_string()))?;

        let private = CFDictionary::from_CFType_pairs(&[
            (
                attr(unsafe { kSecAttrIsPermanent }),
                CFBoolean::true_value().into_CFType(),
            ),
            (
                attr(unsafe { kSecAttrApplicationTag }),
                CFData::from_buffer(tag.as_bytes()).into_CFType(),
            ),
            (attr(unsafe { kSecAttrAccessControl }), access.into_CFType()),
        ]);

        let attributes = CFDictionary::from_CFType_pairs(&[
            (
                attr(unsafe { kSecAttrKeyType }),
                attr_value(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                attr(unsafe { kSecAttrKeySizeInBits }),
                CFNumber::from(256i32).into_CFType(),
            ),
            (
                attr(unsafe { kSecAttrTokenID }),
                attr_value(unsafe { kSecAttrTokenIDSecureEnclave }),
            ),
            (
                attr(unsafe { kSecUseDataProtectionKeychain }),
                CFBoolean::true_value().into_CFType(),
            ),
            (attr(unsafe { kSecPrivateKeyAttrs }), private.into_CFType()),
        ]);

        let mut trouble: CFErrorRef = std::ptr::null_mut();
        let key = unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut trouble) };
        if key.is_null() {
            if !trouble.is_null() {
                drop(unsafe { CFError::wrap_under_create_rule(trouble) });
            }
            return Err(Error::Unavailable(NO_ENCLAVE.to_string()));
        }
        Ok(unsafe { SecKey::wrap_under_create_rule(key) })
    }

    /// A Secure Enclave key lives in the data protection keychain, and on macOS
    /// a search only reaches it — and only returns a key reference — when the
    /// query says so.
    fn query(tag: &str, want_the_key: bool) -> CFDictionary<CFString, CFType> {
        let mut pairs = vec![
            (
                attr(unsafe { kSecClass }),
                attr_value(unsafe { kSecClassKey }),
            ),
            (
                attr(unsafe { kSecAttrApplicationTag }),
                CFData::from_buffer(tag.as_bytes()).into_CFType(),
            ),
            (
                attr(unsafe { kSecAttrKeyType }),
                attr_value(unsafe { kSecAttrKeyTypeECSECPrimeRandom }),
            ),
            (
                attr(unsafe { kSecUseDataProtectionKeychain }),
                CFBoolean::true_value().into_CFType(),
            ),
        ];
        if want_the_key {
            pairs.push((
                attr(unsafe { kSecReturnRef }),
                CFBoolean::true_value().into_CFType(),
            ));
        }
        CFDictionary::from_CFType_pairs(&pairs)
    }
}

mod keychain {
    use super::*;

    const ACCOUNT: &str = "sealing key";
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;

    pub(super) fn seal(tag: &str, plaintext: &[u8]) -> Result<SealResponse> {
        let key = key_or_new(tag)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);

        Ok(SealResponse {
            sealed: sealed::format(KEYCHAIN_SCHEME, &payload),
            backing: Backing::System,
        })
    }

    pub(super) fn open(tag: &str, payload: &[u8]) -> Result<Opened> {
        if payload.len() < NONCE_LEN {
            return Err(Error::Crypto(sealed::FOREIGN.to_string()));
        }
        let (nonce, ciphertext) = payload.split_at(NONCE_LEN);

        let key = existing_key(tag)?.ok_or_else(|| Error::NotFound(NO_SECRET.to_string()))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

        Ok(Opened {
            plaintext: Zeroizing::new(plaintext),
            backing: Backing::System,
        })
    }

    pub(super) fn delete(tag: &str) -> Result<bool> {
        match delete_generic_password(tag, ACCOUNT) {
            Ok(()) => Ok(true),
            Err(why) if why.code() == errSecItemNotFound => Ok(false),
            Err(_) => Err(Error::Unavailable(NO_STORE.to_string())),
        }
    }

    fn existing_key(tag: &str) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let held = match get_generic_password(tag, ACCOUNT) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(why) if why.code() == errSecItemNotFound => return Ok(None),
            Err(_) => return Err(Error::Unavailable(NO_STORE.to_string())),
        };
        if held.len() != KEY_LEN {
            return Err(Error::Crypto(DAMAGED_KEY.to_string()));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&held);
        Ok(Some(key))
    }

    fn key_or_new(tag: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        if let Some(key) = existing_key(tag)? {
            return Ok(key);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(key.as_mut_slice());
        set_generic_password(tag, ACCOUNT, key.as_slice())
            .map_err(|_| Error::Unavailable(NO_STORE.to_string()))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused() -> Error {
        Error::Unavailable("nothing here".to_string())
    }

    #[test]
    fn takes_the_first_rung_that_answers() {
        let mut tried = Vec::new();
        let rung = descend(|rung| {
            tried.push(rung);
            Ok(rung)
        })
        .unwrap();
        assert_eq!(rung, Rung::Enclave);
        assert_eq!(tried, vec![Rung::Enclave]);
    }

    #[test]
    fn falls_past_a_rung_that_refuses() {
        let mut tried = Vec::new();
        let rung = descend(|rung| {
            tried.push(rung);
            if rung == Rung::Enclave {
                Err(refused())
            } else {
                Ok(rung)
            }
        })
        .unwrap();
        assert_eq!(rung, Rung::Keychain);
        assert_eq!(tried, vec![Rung::Enclave, Rung::Keychain]);
    }

    #[test]
    fn falls_all_the_way_to_the_key_file() {
        let rung = descend(|rung| {
            if rung == Rung::KeyFile {
                Ok(rung)
            } else {
                Err(refused())
            }
        })
        .unwrap();
        assert_eq!(rung, Rung::KeyFile);
    }

    #[test]
    fn gives_the_last_refusal_when_no_rung_answers() {
        let mut tried = Vec::new();
        let why = descend(|rung: Rung| -> Result<Rung> {
            tried.push(rung);
            Err(Error::Unavailable(std::format!("{rung:?} said no")))
        })
        .unwrap_err();
        assert_eq!(tried, vec![Rung::Enclave, Rung::Keychain, Rung::KeyFile]);
        assert_eq!(why.to_string(), "KeyFile said no");
    }

    // The rungs below a refusal are still cleared — and the refusal is still
    // said, because a store that refused may be holding the secret yet.
    #[test]
    fn clears_the_lower_rungs_when_the_top_one_refuses() {
        let mut swept = Vec::new();
        let why = sweep(|rung| {
            swept.push(rung);
            match rung {
                Rung::Enclave => Err(refused()),
                Rung::Keychain => Ok(true),
                Rung::KeyFile => Ok(false),
            }
        })
        .unwrap_err();
        assert_eq!(swept, vec![Rung::Enclave, Rung::Keychain, Rung::KeyFile]);
        assert_eq!(why.to_string(), refused().to_string());
    }

    #[test]
    fn deleting_what_is_not_there_succeeds() {
        assert!(!sweep(|_| Ok(false)).unwrap());
    }

    // A store that refused is a store that may still be holding the secret, so
    // it is said — never reported as nothing having been there.
    #[test]
    fn one_store_refusing_is_a_refusal_though_the_others_answered() {
        let why = sweep(|rung| {
            if rung == Rung::Keychain {
                Err(Error::Unavailable(std::format!("{rung:?} said no")))
            } else {
                Ok(false)
            }
        })
        .unwrap_err();
        assert_eq!(why.to_string(), "Keychain said no");
    }

    #[test]
    fn opens_each_scheme_on_the_rung_that_wrote_it() {
        assert_eq!(rung_that_wrote(ENCLAVE_SCHEME), Some(Rung::Enclave));
        assert_eq!(rung_that_wrote(KEYCHAIN_SCHEME), Some(Rung::Keychain));
        assert_eq!(rung_that_wrote(software::SCHEME), Some(Rung::KeyFile));
    }

    #[test]
    fn opens_nothing_another_platform_sealed() {
        for scheme in ["aes-gcm-keystore", "rsa-oaep-tpm", "dpapi"] {
            assert_eq!(rung_that_wrote(scheme), None, "{scheme}");
        }
    }

    #[test]
    fn every_scheme_this_platform_writes_can_be_opened() {
        for rung in LADDER {
            let scheme = match rung {
                Rung::Enclave => ENCLAVE_SCHEME,
                Rung::Keychain => KEYCHAIN_SCHEME,
                Rung::KeyFile => software::SCHEME,
            };
            assert_eq!(rung_that_wrote(scheme), Some(rung));
            assert!(
                sealed::parse(&sealed::format(scheme, b"payload")).is_ok(),
                "{scheme}"
            );
        }
    }
}
