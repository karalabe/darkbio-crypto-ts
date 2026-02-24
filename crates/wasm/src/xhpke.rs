// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HPKE cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9180

use darkbio_crypto::xhpke;
use wasm_bindgen::prelude::*;

/// Size of the secret key seed in bytes.
#[wasm_bindgen]
pub fn xhpke_secret_key_size() -> usize {
    xhpke::SECRET_KEY_SIZE
}

/// Size of the public key in bytes.
#[wasm_bindgen]
pub fn xhpke_public_key_size() -> usize {
    xhpke::PUBLIC_KEY_SIZE
}

/// Size of the encapsulated key in bytes.
#[wasm_bindgen]
pub fn xhpke_encap_key_size() -> usize {
    xhpke::ENCAP_KEY_SIZE
}

/// Size of the fingerprint in bytes.
#[wasm_bindgen]
pub fn xhpke_fingerprint_size() -> usize {
    xhpke::FINGERPRINT_SIZE
}

/// Generates a new random private key.
#[wasm_bindgen]
pub fn xhpke_generate() -> Vec<u8> {
    xhpke::SecretKey::generate().to_bytes().to_vec()
}

/// Derives the public key from a secret key.
#[wasm_bindgen]
pub fn xhpke_public_key(secret_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
    let sk = xhpke::SecretKey::from_bytes(&seed);
    Ok(sk.public_key().to_bytes().to_vec())
}

/// Computes the fingerprint (SHA-256 hash) of a public key.
#[wasm_bindgen]
pub fn xhpke_fingerprint(public_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.fingerprint().to_bytes().to_vec())
}

/// Seals (encrypts) a message to a public key.
/// Returns: encapsulated key (1120 bytes) || ciphertext
#[wasm_bindgen]
pub fn xhpke_seal(
    public_key: &[u8],
    msg_to_seal: &[u8],
    msg_to_auth: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    let pk_bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let (encap_key, ciphertext) = pk
        .seal(msg_to_seal, msg_to_auth, domain)
        .map_err(|e| JsError::new(&format!("seal failed: {:?}", e)))?;

    let mut result = Vec::with_capacity(encap_key.len() + ciphertext.len());
    result.extend_from_slice(&encap_key);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Opens (decrypts) a sealed message with a secret key.
/// Input: encapsulated key (1120 bytes) || ciphertext
#[wasm_bindgen]
pub fn xhpke_open(
    secret_key: &[u8],
    sealed: &[u8],
    msg_to_auth: &[u8],
    domain: &[u8],
) -> Result<Vec<u8>, JsError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
    let sk = xhpke::SecretKey::from_bytes(&seed);

    if sealed.len() < xhpke::ENCAP_KEY_SIZE {
        return Err(JsError::new("sealed data too short"));
    }
    let session_key: [u8; 1120] = sealed[..xhpke::ENCAP_KEY_SIZE]
        .try_into()
        .map_err(|_| JsError::new("invalid encapsulated key"))?;
    let ciphertext = &sealed[xhpke::ENCAP_KEY_SIZE..];

    sk.open(&session_key, ciphertext, msg_to_auth, domain)
        .map_err(|e| JsError::new(&format!("open failed: {:?}", e)))
}

/// Creates an HPKE sender context for multi-message encryption to the given
/// public key. Returns an opaque `XhpkeSender` that holds both the encryption
/// context and the 1120-byte encapsulated key (retrievable via `encap_key()`).
///
/// Messages encrypted with the returned sender must be decrypted in order by
/// the corresponding receiver context.
#[wasm_bindgen]
pub fn xhpke_new_sender(public_key: &[u8], domain: &[u8]) -> Result<XhpkeSender, JsError> {
    let pk_bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let (sender, encap_key) = pk
        .new_sender(domain)
        .map_err(|e| JsError::new(&format!("new_sender failed: {:?}", e)))?;

    Ok(XhpkeSender {
        inner: sender,
        encap_key: encap_key.to_vec(),
    })
}

/// Creates an HPKE receiver context for multi-message decryption using the
/// given secret key and encapsulated key. Messages must be decrypted in the
/// same order they were encrypted by the corresponding sender.
#[wasm_bindgen]
pub fn xhpke_new_receiver(
    secret_key: &[u8],
    encap_key: &[u8],
    domain: &[u8],
) -> Result<XhpkeReceiver, JsError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
    let sk = xhpke::SecretKey::from_bytes(&seed);

    let encap_key_array: [u8; 1120] = encap_key
        .try_into()
        .map_err(|_| JsError::new("encapsulated key must be 1120 bytes"))?;

    let receiver = sk
        .new_receiver(&encap_key_array, domain)
        .map_err(|e| JsError::new(&format!("new_receiver failed: {:?}", e)))?;

    Ok(XhpkeReceiver { inner: receiver })
}

/// Stateful HPKE sender for multi-message encryption. Each call to `seal`
/// uses an auto-incrementing nonce, producing unique ciphertexts even for
/// identical plaintexts.
#[wasm_bindgen]
pub struct XhpkeSender {
    inner: xhpke::Sender,
    encap_key: Vec<u8>,
}

#[wasm_bindgen]
impl XhpkeSender {
    /// Returns the 1120-byte encapsulated key that must be transmitted to the
    /// receiver so it can create the corresponding decryption context.
    pub fn encap_key(&self) -> Vec<u8> {
        self.encap_key.clone()
    }

    /// Encrypts a message using the next nonce in the sequence.
    pub fn seal(&mut self, msg_to_seal: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .seal(msg_to_seal, msg_to_auth)
            .map_err(|e| JsError::new(&format!("seal failed: {:?}", e)))
    }
}

/// Stateful HPKE receiver for multi-message decryption. Each call to `open`
/// uses an auto-incrementing nonce. Messages must be provided in the same
/// order they were sealed by the corresponding sender.
#[wasm_bindgen]
pub struct XhpkeReceiver {
    inner: xhpke::Receiver,
}

#[wasm_bindgen]
impl XhpkeReceiver {
    /// Decrypts a message using the next nonce in the sequence.
    pub fn open(&mut self, msg_to_open: &[u8], msg_to_auth: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .open(msg_to_open, msg_to_auth)
            .map_err(|e| JsError::new(&format!("open failed: {:?}", e)))
    }
}

/// Parses a secret key from PEM format.
#[wasm_bindgen]
pub fn xhpke_secret_key_from_pem(pem: &str) -> Result<Vec<u8>, JsError> {
    let sk = xhpke::SecretKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(sk.to_bytes().to_vec())
}

/// Serializes a secret key to PEM format.
#[wasm_bindgen]
pub fn xhpke_secret_key_to_pem(secret_key: &[u8]) -> Result<String, JsError> {
    let seed: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| JsError::new("secret key must be 32 bytes"))?;
    let sk = xhpke::SecretKey::from_bytes(&seed);
    Ok(sk.to_pem())
}

/// Parses a public key from PEM format.
#[wasm_bindgen]
pub fn xhpke_public_key_from_pem(pem: &str) -> Result<Vec<u8>, JsError> {
    let pk = xhpke::PublicKey::from_pem(pem).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.to_bytes().to_vec())
}

/// Serializes a public key to PEM format.
#[wasm_bindgen]
pub fn xhpke_public_key_to_pem(public_key: &[u8]) -> Result<String, JsError> {
    let bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&bytes).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(pk.to_pem())
}

/// Parses a public key from a PEM-encoded X.509 certificate, verifying the signature.
/// Returns: public key (1216 bytes) || not_before (8 bytes BE) || not_after (8 bytes BE)
#[wasm_bindgen]
pub fn xhpke_public_key_from_cert_pem(pem: &str, signer: &[u8]) -> Result<Vec<u8>, JsError> {
    use darkbio_crypto::{x509, xdsa};

    let signer_bytes: [u8; 1984] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 1984 bytes"))?;
    let signer_pk =
        xdsa::PublicKey::from_bytes(&signer_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let verified = xhpke::verify_cert_pem(pem, &signer_pk, x509::ValidityCheck::Disabled)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut result = Vec::with_capacity(1216 + 16);
    result.extend_from_slice(&verified.public_key.to_bytes());
    result.extend_from_slice(&verified.cert.not_before.to_be_bytes());
    result.extend_from_slice(&verified.cert.not_after.to_be_bytes());
    Ok(result)
}

/// Parses a public key from a DER-encoded X.509 certificate, verifying the signature.
/// Returns: public key (1216 bytes) || not_before (8 bytes BE) || not_after (8 bytes BE)
#[wasm_bindgen]
pub fn xhpke_public_key_from_cert_der(der: &[u8], signer: &[u8]) -> Result<Vec<u8>, JsError> {
    use darkbio_crypto::{x509, xdsa};

    let signer_bytes: [u8; 1984] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 1984 bytes"))?;
    let signer_pk =
        xdsa::PublicKey::from_bytes(&signer_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let verified = xhpke::verify_cert_der(der, &signer_pk, x509::ValidityCheck::Disabled)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut result = Vec::with_capacity(1216 + 16);
    result.extend_from_slice(&verified.public_key.to_bytes());
    result.extend_from_slice(&verified.cert.not_before.to_be_bytes());
    result.extend_from_slice(&verified.cert.not_after.to_be_bytes());
    Ok(result)
}

/// Generates a PEM-encoded X.509 certificate for a public key, signed by an xDSA issuer.
/// Note: HPKE certificates are always end-entity certificates (is_ca is ignored).
#[wasm_bindgen]
pub fn xhpke_public_key_to_cert_pem(
    public_key: &[u8],
    signer: &[u8],
    subject_name: &str,
    issuer_name: &str,
    not_before: u64,
    not_after: u64,
) -> Result<String, JsError> {
    use darkbio_crypto::{x509, xdsa};

    let pk_bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let signer_seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let signer_sk = xdsa::SecretKey::from_bytes(&signer_seed);

    let template = x509::Certificate {
        subject: x509::Name::new().cn(subject_name),
        issuer: x509::Name::new().cn(issuer_name),
        not_before,
        not_after,
        role: x509::Role::Leaf,
        ..Default::default()
    };
    xhpke::issue_cert_pem(&pk, &signer_sk, &template).map_err(|e| JsError::new(&e.to_string()))
}

/// Generates a DER-encoded X.509 certificate for a public key, signed by an xDSA issuer.
/// Note: HPKE certificates are always end-entity certificates (is_ca is ignored).
#[wasm_bindgen]
pub fn xhpke_public_key_to_cert_der(
    public_key: &[u8],
    signer: &[u8],
    subject_name: &str,
    issuer_name: &str,
    not_before: u64,
    not_after: u64,
) -> Result<Vec<u8>, JsError> {
    use darkbio_crypto::{x509, xdsa};

    let pk_bytes: [u8; 1216] = public_key
        .try_into()
        .map_err(|_| JsError::new("public key must be 1216 bytes"))?;
    let pk = xhpke::PublicKey::from_bytes(&pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;

    let signer_seed: [u8; 64] = signer
        .try_into()
        .map_err(|_| JsError::new("signer must be 64 bytes"))?;
    let signer_sk = xdsa::SecretKey::from_bytes(&signer_seed);

    let template = x509::Certificate {
        subject: x509::Name::new().cn(subject_name),
        issuer: x509::Name::new().cn(issuer_name),
        not_before,
        not_after,
        role: x509::Role::Leaf,
        ..Default::default()
    };
    xhpke::issue_cert_der(&pk, &signer_sk, &template).map_err(|e| JsError::new(&e.to_string()))
}
