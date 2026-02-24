// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CWT (CBOR Web Token) wrappers on top of COSE Sign1.
//!
//! https://datatracker.ietf.org/doc/html/rfc8392

use darkbio_crypto::{cbor, cwt, xdsa};
use wasm_bindgen::prelude::*;

/// Issues a CWT by signing pre-encoded CBOR claims with COSE Sign1.
///
/// - `claims_cbor`: CBOR-encoded claims map
/// - `signer`: 64-byte xDSA secret key seed
/// - `domain`: Application-specific domain separator
#[wasm_bindgen]
pub fn cwt_issue(claims_cbor: &[u8], signer: &[u8], domain: &[u8]) -> Result<Vec<u8>, JsError> {
    cbor::verify(claims_cbor).map_err(|e| JsError::new(&format!("invalid claims CBOR: {}", e)))?;

    let seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let sk = xdsa::SecretKey::from_bytes(&seed);

    cwt::issue(&cbor::Raw(claims_cbor.to_vec()), &sk, domain)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Verifies a CWT's COSE signature and temporal validity, returning
/// the raw CBOR-encoded claims.
///
/// When `now` is provided, temporal claims are validated: nbf must be
/// present and `nbf <= now`, and if exp is present then `now < exp`.
/// When `now` is `None`, temporal validation is skipped.
///
/// - `token`: The serialized CWT
/// - `verifier`: 1984-byte xDSA public key
/// - `domain`: Application-specific domain separator
/// - `now`: Current Unix timestamp for temporal validation (None to skip)
#[wasm_bindgen]
pub fn cwt_verify(
    token: &[u8],
    verifier: &[u8],
    domain: &[u8],
    now: Option<u64>,
) -> Result<Vec<u8>, JsError> {
    let pk_bytes: [u8; 1984] = verifier
        .try_into()
        .map_err(|_| JsError::new("verifier must be 1984 bytes"))?;
    let pk = xdsa::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let raw: cbor::Raw =
        cwt::verify(token, &pk, domain, now).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(raw.0)
}

/// Extracts the signer's fingerprint from a CWT without verifying.
///
/// The returned data is unauthenticated.
#[wasm_bindgen]
pub fn cwt_signer(token: &[u8]) -> Result<Vec<u8>, JsError> {
    let fp = cwt::signer(token).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(fp.to_bytes().to_vec())
}

/// Extracts and decodes claims from a CWT without verifying the signature.
///
/// **Warning**: The returned payload is unauthenticated and should not be
/// trusted until verified with `cwt_verify`.
#[wasm_bindgen]
pub fn cwt_peek(token: &[u8]) -> Result<Vec<u8>, JsError> {
    let raw: cbor::Raw = cwt::peek(token).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(raw.0)
}
