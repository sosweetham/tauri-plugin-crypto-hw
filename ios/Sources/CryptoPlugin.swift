//
//  CryptoPlugin.swift
//  tauri-plugin-crypto-hw
//
//  Created by SoSweetHam on 05/05/25.
//

import SwiftRs
import Tauri
import UIKit
import WebKit
import Security

let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage],
    nil
)!

enum CryptoPluginError: Error {
    case keyExists
    case generationFailed
    case badPayload
    case badSignature
    case noSecret
    case foreignSecret
    case malformedSecret
    case unknown
}

/// What a sealed string from the Secure Enclave names itself. src/sealed.rs is
/// the Rust side of the same two-part string.
let sealScheme = "ecies-p256"

let eciesAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

func formatSealed(_ bytes: Data) -> String {
    let payload = bytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "\(sealScheme):\(payload)"
}

func parseSealed(_ text: String) throws -> Data {
    guard let colon = text.firstIndex(of: ":") else {
        throw CryptoPluginError.malformedSecret
    }
    guard String(text[text.startIndex..<colon]) == sealScheme else {
        throw CryptoPluginError.foreignSecret
    }
    var padded = String(text[text.index(after: colon)...])
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while padded.count % 4 != 0 {
        padded += "="
    }
    guard let bytes = Data(base64Encoded: padded) else {
        throw CryptoPluginError.malformedSecret
    }
    return bytes
}

class IncludesIdentifier: Decodable {
    let identifier: String
}

class SignRequest: Decodable {
    let identifier: String
    let payload: String
}

class VerifySignatureRequest: Decodable {
    let identifier: String
    let payload: String
    let signature: String
}

class SealRequest: Decodable {
    let identifier: String
    let plaintext: String
}

class OpenRequest: Decodable {
    let identifier: String
    let sealed: String
}

class CryptoPlugin: Plugin {
    private func buildKeyTag(from tag: String) -> Data? {
        guard let bundleID = Bundle.main.bundleIdentifier else { return nil }
        let fullTag = "\(bundleID).\(tag)"
        return fullTag.data(using: .utf8)
    }
    
    private func keyExistsInKeychain(tag: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnRef as String: false
        ]
        
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    private func generateSecureEnclaveKey(tag: Data) throws {
        if keyExistsInKeychain(tag: tag) {
            throw CryptoPluginError.keyExists
        }

        var error: Unmanaged<CFError>?
        let attributes: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeEC,
                kSecAttrKeySizeInBits: 256,
                kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs: [
                    kSecAttrIsPermanent: true,
                    kSecAttrApplicationTag: tag,
                    kSecAttrAccessControl: access
                ]
        ]
        guard SecKeyCreateRandomKey(attributes, &error) != nil else {
            throw CryptoPluginError.generationFailed
        }
    }
    
    private func getPrivateKeyReference(tag: Data) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
                throw CryptoPluginError.unknown
            }
            
        return (item as! SecKey)
    }
    
    private func getPublicKey(tag: Data) throws -> String {
        let privKeyRef = try getPrivateKeyReference(tag: tag)
        guard let publicKey = SecKeyCopyPublicKey(privKeyRef) else {
            throw CryptoPluginError.unknown
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw CryptoPluginError.unknown
        }
        
        return dataToMultibaseHex(publicKeyData)
    }
    
    private func _signPayload(tag: Data, payload: String) throws -> String {
        guard let data = payload.data(using: .utf8) else {
            throw CryptoPluginError.badPayload
        }
        
        let privKeyRef = try getPrivateKeyReference(tag: tag)
        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(
            privKeyRef,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            throw CryptoPluginError.unknown
        }
        
        return base58btcMultibaseEncode(signatureData)
    }
    
    private func _verifySignature(tag: Data, payload: String, signature: String) throws -> Bool {
        guard let payloadData = payload.data(using: .utf8) else {
            throw CryptoPluginError.badPayload
        }
        
        guard let signatureData = base58btcMultibaseDecode(signature) else {
            throw CryptoPluginError.badSignature
        }
        
        let privKeyRef = try getPrivateKeyReference(tag: tag)
        guard let publicKey = SecKeyCopyPublicKey(privKeyRef) else {
            throw CryptoPluginError.unknown
        }
        
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            payloadData as CFData,
            signatureData as CFData,
            &error
        )
        return result
        
    }

    /// Sealing and signing each get their own key under one identifier.
    private func buildSealTag(from identifier: String) -> Data? {
        return buildKeyTag(from: "\(identifier).seal")
    }

    private func sealingKey(tag: Data) throws -> SecKey {
        if !keyExistsInKeychain(tag: tag) {
            try generateSecureEnclaveKey(tag: tag)
        }
        return try getPrivateKeyReference(tag: tag)
    }

    private func deleteKey(tag: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC
        ]

        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }

    private func _seal(tag: Data, plaintext: Data) throws -> String {
        let privKeyRef = try sealingKey(tag: tag)
        guard let publicKey = SecKeyCopyPublicKey(privKeyRef) else {
            throw CryptoPluginError.unknown
        }

        var error: Unmanaged<CFError>?
        guard let ciphertext = SecKeyCreateEncryptedData(
            publicKey,
            eciesAlgorithm,
            plaintext as CFData,
            &error
        ) as Data? else {
            error?.release()
            throw CryptoPluginError.unknown
        }

        return formatSealed(ciphertext)
    }

    private func _open(tag: Data, sealed: String) throws -> Data {
        let payload = try parseSealed(sealed)
        guard keyExistsInKeychain(tag: tag) else {
            throw CryptoPluginError.noSecret
        }

        let privKeyRef = try getPrivateKeyReference(tag: tag)
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            privKeyRef,
            eciesAlgorithm,
            payload as CFData,
            &error
        ) as Data? else {
            error?.release()
            throw CryptoPluginError.badPayload
        }

        return plaintext
    }

    @objc public func generate(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncludesIdentifier.self)
        let tag = buildKeyTag(from: args.identifier)
        if tag == nil {
            invoke.reject("Invalid identifier provided")
            return
        }
        do {
            try generateSecureEnclaveKey(tag: tag!)
            invoke.resolve(["message": "Key generated successfully"])
            return
        } catch CryptoPluginError.keyExists {
            invoke.resolve(["message": "Key already exists"])
            return
        } catch {
            invoke.reject("Key generation failed")
            return
        }
    }

    @objc public func exists(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncludesIdentifier.self)
        let tag = buildKeyTag(from: args.identifier)
        if tag == nil {
            invoke.reject("Invalid identifier provided")
            return
        }
        let exists = keyExistsInKeychain(tag: tag!)
        invoke.resolve(["exists": exists])
    }
    
    @objc public func getPublicKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncludesIdentifier.self)
        let tag = buildKeyTag(from: args.identifier)
        if tag == nil {
            invoke.reject("Invalid identifier provided")
            return
        }
        let publicKeyData: String
        do {
            publicKeyData = try getPublicKey(tag: tag!)
        } catch {
            invoke.reject("Couldn't retrieve public key")
            return
        }
        invoke.resolve([
            "publicKey": publicKeyData,
        ])
    }
    
    @objc public func signPayload(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignRequest.self)
        let tag = buildKeyTag(from: args.identifier)
        if tag == nil {
            invoke.reject("Invalid identifier provided")
            return
        }
        let signature: String
        do {
            signature = try _signPayload(tag: tag!, payload: args.payload)
        } catch {
            invoke.reject("Couldn't create signature for the payload")
            return
        }
        invoke.resolve([
            "signature": signature
        ])
    }
    
    @objc public func verifySignature(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(VerifySignatureRequest.self)
        let tag = buildKeyTag(from: args.identifier)
        if tag == nil {
            invoke.reject("Invalid identifier provided")
            return
        }
        let result: Bool
        do {
            result = try _verifySignature(tag: tag!, payload: args.payload, signature: args.signature)
        } catch {
            invoke.reject("Couldn't verify payload")
            return
        }
        invoke.resolve([
            "valid": result
        ])
    }

    @objc public func seal(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SealRequest.self)
        guard let tag = buildSealTag(from: args.identifier) else {
            invoke.reject("Invalid identifier provided")
            return
        }
        guard var plaintext = args.plaintext.data(using: .utf8) else {
            invoke.reject("That secret is not text.")
            return
        }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }

        let sealed: String
        do {
            sealed = try _seal(tag: tag, plaintext: plaintext)
        } catch {
            invoke.reject("This device would not keep that secret. Try again.")
            return
        }
        invoke.resolve([
            "sealed": sealed,
            "backing": "hardware"
        ])
    }

    @objc public func open(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(OpenRequest.self)
        guard let tag = buildSealTag(from: args.identifier) else {
            invoke.reject("Invalid identifier provided")
            return
        }

        var plaintext: Data
        do {
            plaintext = try _open(tag: tag, sealed: args.sealed)
        } catch CryptoPluginError.noSecret {
            invoke.reject("There is no secret kept under that name on this device.")
            return
        } catch CryptoPluginError.foreignSecret {
            invoke.reject("This was sealed on a different device or in a different way.")
            return
        } catch CryptoPluginError.malformedSecret {
            invoke.reject("This is not a sealed secret from this app.")
            return
        } catch {
            invoke.reject("That secret could not be opened. Seal it again.")
            return
        }
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }

        guard let text = String(data: plaintext, encoding: .utf8) else {
            invoke.reject("That secret is not text.")
            return
        }
        invoke.resolve([
            "plaintext": text,
            "backing": "hardware"
        ])
    }

    @objc public func delete(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(IncludesIdentifier.self)
        guard let sealTag = buildSealTag(from: args.identifier),
              let signingTag = buildKeyTag(from: args.identifier) else {
            invoke.reject("Invalid identifier provided")
            return
        }
        let hadSealingKey = deleteKey(tag: sealTag)
        let hadSigningKey = deleteKey(tag: signingTag)
        invoke.resolve([
            "deleted": hadSealingKey || hadSigningKey
        ])
    }
}

@_cdecl("init_plugin_crypto")
func initPlugin() -> Plugin {
    return CryptoPlugin()
}
