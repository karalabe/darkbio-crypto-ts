// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Tiny CBOR encoder and decoder.
//!
//! https://datatracker.ietf.org/doc/html/rfc8949
//!
//! This is an implementation of the CBOR spec with an extremely reduced type
//! system, focusing on security rather than flexibility or completeness. The
//! following types are supported:
//! - Booleans:                bool
//! - Null:                    Option<T>::None, cbor::Null
//! - 64bit positive integers: u64
//! - 64bit signed integers:   i64
//! - UTF-8 text strings:      String, &str
//! - Byte strings:            Vec<u8>, &[u8], [u8; N]
//! - Arrays:                  (), (X,), (X,Y), ... tuples, or structs with #[cbor(array)]
//! - Maps:                    structs with #[cbor(key = N)] fields

use darkbio_crypto::cbor;
use wasm_bindgen::prelude::*;

/// Verifies that data is valid CBOR using the restricted type system.
#[wasm_bindgen]
pub fn cbor_verify(data: &[u8]) -> Result<(), JsError> {
    cbor::verify(data).map_err(|e| JsError::new(&e.to_string()))
}
