// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE wrappers for xDSA and xHPKE.
//!
//! https://datatracker.ietf.org/doc/html/rfc8152
//! https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke

use darkbio_crypto::{cbor, cose, xdsa, xhpke};
use wasm_bindgen::prelude::*;

/// Creates a COSE_Sign1 signature with an embedded payload.
#[wasm_bindgen]
pub fn cose_sign(
    msg_to_embed: &[u8],
    msg_to_auth: &[u8],
    signer: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_embed)
        .map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);

    cose::sign(
        cbor::Raw(msg_to_embed.to_vec()),
        cbor::Raw(msg_to_auth.to_vec()),
        &sk,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Creates a COSE_Sign1 signature without an embedded payload (detached mode).
#[wasm_bindgen]
pub fn cose_sign_detached(
    msg_to_auth: &[u8],
    signer: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);

    cose::sign_detached(cbor::Raw(msg_to_auth.to_vec()), &sk, domain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a COSE_Sign1 signature and returns the embedded payload.
#[wasm_bindgen]
pub fn cose_verify(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &[u8],
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let pk_bytes: [u8; 1984] = verifier
        .try_into()
        .map_err(|_| JsError::new("verifier must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let raw: cbor::Raw = cose::verify(
        msg_to_check,
        cbor::Raw(msg_to_auth.to_vec()),
        &pk,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(raw.0)
}

/// Verifies a COSE_Sign1 signature with a detached payload.
#[wasm_bindgen]
pub fn cose_verify_detached(
    msg_to_check: &[u8],
    msg_to_auth: &[u8],
    verifier: &[u8],
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<(), JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let pk_bytes: [u8; 1984] = verifier
        .try_into()
        .map_err(|_| JsError::new("verifier must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    cose::verify_detached(
        msg_to_check,
        cbor::Raw(msg_to_auth.to_vec()),
        &pk,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Extracts the signer's fingerprint from a COSE_Sign1 without verifying.
#[wasm_bindgen]
pub fn cose_signer(signature: &[u8]) -> Result<Vec<u8>, JsError> {
    let fp = cose::signer(signature).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(fp.to_bytes().to_vec())
}

/// Extracts the embedded payload from a COSE_Sign1 without verifying.
#[wasm_bindgen]
pub fn cose_peek(signature: &[u8]) -> Result<Vec<u8>, JsError> {
    let raw: cbor::Raw = cose::peek(signature).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(raw.0)
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
#[wasm_bindgen]
pub fn cose_recipient(ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let fp = cose::recipient(ciphertext).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(fp.to_bytes().to_vec())
}

/// Signs a message then encrypts it to a recipient (sign-then-encrypt).
#[wasm_bindgen]
pub fn cose_seal(
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    signer: &[u8],
    recipient: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_seal).map_err(|e| JsError::new(&format!("invalid payload CBOR: {}", e)))?;
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let signer_seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let signer_sk = xdsa::SecretKey::from_bytes(&signer_seed);

    let recipient_bytes: [u8; 1216] = recipient
        .try_into()
        .map_err(|_| JsError::new("recipient must be 1216 bytes"))?;
    let recipient_pk =
        xhpke::PublicKey::from_bytes(&recipient_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    cose::seal(
        cbor::Raw(msg_to_seal.to_vec()),
        cbor::Raw(msg_to_auth.to_vec()),
        &signer_sk,
        &recipient_pk,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts and verifies a sealed message.
#[wasm_bindgen]
pub fn cose_open(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &[u8],
    sender: &[u8],
    domain: &[u8],
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let recipient_seed: [u8; 32] = recipient
        .try_into()
        .map_err(|_| JsError::new("recipient must be 32 bytes"))?;
    let recipient_sk = xhpke::SecretKey::from_bytes(&recipient_seed);

    let sender_bytes: [u8; 1984] = sender
        .try_into()
        .map_err(|_| JsError::new("sender must be 1984 bytes"))?;
    let sender_pk =
        xdsa::PublicKey::from_bytes(&sender_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let raw: cbor::Raw = cose::open(
        msg_to_open,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient_sk,
        &sender_pk,
        domain,
        max_drift_secs,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(raw.0)
}

/// Encrypts an already-signed COSE_Sign1 to a recipient.
#[wasm_bindgen]
pub fn cose_encrypt(
    sign1: &[u8],
    msg_to_auth: &[u8],
    recipient: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let recipient_bytes: [u8; 1216] = recipient
        .try_into()
        .map_err(|_| JsError::new("recipient must be 1216 bytes"))?;
    let recipient_pk =
        xhpke::PublicKey::from_bytes(&recipient_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    cose::encrypt(
        sign1,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient_pk,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypts a sealed message without verifying the signature.
#[wasm_bindgen]
pub fn cose_decrypt(
    msg_to_open: &[u8],
    msg_to_auth: &[u8],
    recipient: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    cbor::verify(msg_to_auth).map_err(|e| JsError::new(&format!("invalid AAD CBOR: {}", e)))?;

    let recipient_seed: [u8; 32] = recipient
        .try_into()
        .map_err(|_| JsError::new("recipient must be 32 bytes"))?;
    let recipient_sk = xhpke::SecretKey::from_bytes(&recipient_seed);

    cose::decrypt(
        msg_to_open,
        cbor::Raw(msg_to_auth.to_vec()),
        &recipient_sk,
        domain,
    )
    .map_err(|e| JsError::new(&e.to_string()))
}
