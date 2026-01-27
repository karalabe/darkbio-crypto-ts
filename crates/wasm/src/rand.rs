// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use wasm_bindgen::prelude::*;

/// Generates an arbitrarily large buffer filled with randomness.
#[wasm_bindgen]
pub fn rand_generate(bytes: usize) -> Vec<u8> {
    darkbio_crypto::rand::generate(bytes)
}
