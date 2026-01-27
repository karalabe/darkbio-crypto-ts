// crypto-ts: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Argon2id cryptography wrappers and parametrization.
//!
//! https://datatracker.ietf.org/doc/html/rfc9106

use wasm_bindgen::prelude::*;

/// Derives a key from the password, salt, and cost parameters using Argon2id,
/// returning a byte array that can be used as a cryptographic key. The CPU cost
/// and parallelism degree must be greater than zero.
///
/// RFC 9106 Section 7.4 recommends time=1, and memory=2048*1024 as a sensible
/// number. If using that amount of memory (2GB) is not possible in some contexts
/// then the time parameter can be increased to compensate.
///
/// The time parameter specifies the number of passes over the memory and the
/// memory parameter specifies the size of the memory in KiB. The number of threads
/// can be adjusted to the numbers of available CPUs. The cost parameters should be
/// increased as memory latency and CPU parallelism increases. Remember to get a
/// good random salt.
#[wasm_bindgen]
pub fn argon2_key(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory: u32,
    threads: u32,
    out_len: usize,
) -> Vec<u8> {
    darkbio_crypto::argon2::key_with_len(password, salt, time, memory, threads, out_len)
}
