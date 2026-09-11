// AEZ v5 (https://www.cs.ucdavis.edu/~rogaway/aez/), the wide-block
// authenticated-encryption scheme that LND's aezeed cipher seed enciphers
// with. Only deciphering is reachable from the WASM exports; the encipher
// path is kept under #[cfg(test)] so the reference test vectors can prove
// both directions of the port.
//
// Provenance and licensing
// ------------------------
//
// This module is vendored from the `zears` crate, version 0.2.1
// (https://codeberg.org/dunj3/zears, MIT License, Copyright 2025 Daniel
// Schadt), a pure-Rust implementation of AEZ v5 validated against test
// vectors generated from the reference implementation
// (https://github.com/nmathewson/aez_test_vectors). It is vendored rather
// than depended on because the crate declares `cpufeatures` unconditionally,
// which fails to compile for wasm32-unknown-unknown; the cipher itself is
// target-independent. Changes from the original, kept reviewable
// file-by-file:
//
// * aesround.rs: the x86_64 AES-NI fast path (the `cpufeatures` user) is
//   removed; the portable software path via the `aes` crate remains.
// * block.rs: the nightly-only `simd` feature branches are removed.
// * lib.rs (this file, as mod.rs): the encrypt convenience methods
//   (encrypt/encrypt_vec/encrypt_inplace/encrypt_buffer), append_auth, and
//   the module documentation are removed; the core encipher path moves under
//   #[cfg(test)]; tests use a local hex helper instead of the `hex` dev
//   dependency; a Drop implementation erases the expanded key schedule
//   (the scrypt-derived key material) when an Aez instance dies; and
//   extract() wipes the Blake2b hasher (whose block buffer holds the raw
//   key) before it drops. The cipher math is otherwise verbatim.
// * accessor.rs, testvectors.rs: verbatim.
//
// Unlike the rest of EntropyLab (public domain, see LICENSE), THIS MODULE IS
// NOT PUBLIC DOMAIN. Copies and derivative works (including the built
// entropylab-wasm artifact, which compiles it in) must retain the following
// notice:
//
//   Copyright 2025 Daniel Schadt
//
//   Permission is hereby granted, free of charge, to any person obtaining a
//   copy of this software and associated documentation files (the
//   "Software"), to deal in the Software without restriction, including
//   without limitation the rights to use, copy, modify, merge, publish,
//   distribute, sublicense, and/or sell copies of the Software, and to
//   permit persons to whom the Software is furnished to do so, subject to
//   the following conditions:
//
//   The above copyright notice and this permission notice shall be included
//   in all copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
//   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
//   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
//   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
//   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
//   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

use constant_time_eq::constant_time_eq;

mod accessor;
mod aesround;
mod block;

#[cfg(test)]
mod testvectors;

use accessor::BlockAccessor;
use aesround::AesRound;
use block::Block;
#[cfg(test)]
type Key = [u8; 48];
type Tweak<'a> = &'a [&'a [u8]];

static ZEROES: [u8; 1024] = [0; 1024];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encipher,
    Decipher,
}

/// AEZ encryption scheme.
pub struct Aez {
    key_i: Block,
    key_j: Block,
    key_l: Block,
    key_l_multiples: [Block; 8],
    aes: aesround::AesImpl,
}

impl Drop for Aez {
    /// Erases the expanded key schedule (scrypt-derived key material) so it
    /// does not outlive the decipher as a residual in linear memory. Not part
    /// of upstream zears; see the provenance notes above.
    fn drop(&mut self) {
        self.key_i.wipe();
        self.key_j.wipe();
        self.key_l.wipe();
        for block in &mut self.key_l_multiples {
            block.wipe();
        }
        self.aes.wipe();
    }
}

impl Aez {
    /// Create a new AEZ instance.
    ///
    /// The key is expanded using Blake2b, according to the AEZ specification.
    ///
    /// If you provide a key of the correct length (48 bytes), no expansion is done and the key is
    /// taken as-is.
    pub fn new(key: &[u8]) -> Self {
        let key = extract(key);
        let (key_i, key_j, key_l) = split_key(&key);
        let aes = aesround::AesImpl::new(key_i, key_j, key_l);
        let key_l_multiples = [
            key_l * 0,
            key_l * 1,
            key_l * 2,
            key_l * 3,
            key_l * 4,
            key_l * 5,
            key_l * 6,
            key_l * 7,
        ];
        Aez {
            key_i,
            key_j,
            key_l,
            key_l_multiples,
            aes,
        }
    }

    /// Decrypts the given ciphertext.
    ///
    /// Parameters:
    ///
    /// * `nonce` -- the nonce used at encryption time.
    /// * `associated_data` -- additional data included in the integrity check.
    /// * `tau` -- number of *bytes* (not bits) used for integrity checking.
    /// * `data` -- the ciphertext to decrypt.
    ///
    /// Returns the decrypted content. If the integrity check fails, returns `None` instead. The
    /// returned vector has length `data.len() - tau`.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[&[u8]],
        tau: u32,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buffer = Vec::from(data);
        let len = match decrypt(self, nonce, associated_data, tau, &mut buffer) {
            None => return None,
            Some(m) => m.len(),
        };
        buffer.truncate(len);
        Some(buffer)
    }
}

fn extract(key: &[u8]) -> [u8; 48] {
    if key.len() == 48 {
        key.try_into().unwrap()
    } else {
        use blake2::Digest;
        type Blake2b384 = blake2::Blake2b<blake2::digest::consts::U48>;
        let mut hasher = Blake2b384::new();
        hasher.update(key);
        // finalize_reset instead of finalize: the hasher's block buffer holds
        // the raw key until it is overwritten, so erase it before dropping.
        // (Not part of upstream zears; see the provenance notes above.)
        let expanded = hasher.finalize_reset();
        crate::wipe_val(&mut hasher);
        expanded.into()
    }
}

#[cfg(test)]
fn encrypt(aez: &Aez, nonce: &[u8], ad: &[&[u8]], tau: u32, buffer: &mut [u8]) {
    // We treat tau as bytes, but according to the spec, tau is actually in bits.
    let tau_block = Block::from_int(tau as u128 * 8);
    let tau_bytes = tau_block.bytes();
    let mut tweaks_vec;
    // We optimize for the common case of having no associated data, or having one item of
    // associated data (which is all the reference implementation supports anyway). If there's more
    // associated data, we cave in and allocate a vec.
    let tweaks = match ad.len() {
        0 => &[&tau_bytes, nonce] as &[&[u8]],
        1 => &[&tau_bytes, nonce, ad[0]],
        _ => {
            tweaks_vec = vec![&tau_bytes, nonce];
            tweaks_vec.extend(ad);
            &tweaks_vec
        }
    };
    assert!(buffer.len() >= tau as usize);
    if buffer.len() == tau as usize {
        // As aez_prf only xor's the input in, we have to clear the buffer first
        buffer.fill(0);
        aez_prf(aez, tweaks, buffer);
    } else {
        encipher(aez, tweaks, buffer);
    }
}

fn decrypt<'a>(
    aez: &Aez,
    nonce: &[u8],
    ad: &[&[u8]],
    tau: u32,
    ciphertext: &'a mut [u8],
) -> Option<&'a [u8]> {
    if ciphertext.len() < tau as usize {
        return None;
    }

    let tau_block = Block::from_int(tau * 8);
    let tau_bytes = tau_block.bytes();
    let mut tweaks_vec;
    let tweaks = match ad.len() {
        0 => &[&tau_bytes, nonce] as &[&[u8]],
        1 => &[&tau_bytes, nonce, ad[0]],
        _ => {
            tweaks_vec = vec![&tau_bytes, nonce];
            tweaks_vec.extend(ad);
            &tweaks_vec
        }
    };

    if ciphertext.len() == tau as usize {
        aez_prf(aez, tweaks, ciphertext);
        if is_zeroes(ciphertext) {
            return Some(&[]);
        } else {
            return None;
        }
    }

    decipher(aez, tweaks, ciphertext);
    let (m, auth) = ciphertext.split_at(ciphertext.len() - tau as usize);
    assert!(auth.len() == tau as usize);

    if is_zeroes(auth) { Some(m) } else { None }
}

fn is_zeroes(data: &[u8]) -> bool {
    let comparator = if data.len() <= ZEROES.len() {
        &ZEROES[..data.len()]
    } else {
        // We should find a way to do this without allocating a separate buffer full of zeroes, but
        // I don't want to hand-roll my constant-time-is-zeroes yet.
        &vec![0; data.len()]
    };
    constant_time_eq(data, comparator)
}

#[cfg(test)]
fn encipher(aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    if message.len() < 256 / 8 {
        cipher_aez_tiny(Mode::Encipher, aez, tweaks, message)
    } else {
        cipher_aez_core(Mode::Encipher, aez, tweaks, message)
    }
}

fn decipher(aez: &Aez, tweaks: Tweak, buffer: &mut [u8]) {
    if buffer.len() < 256 / 8 {
        cipher_aez_tiny(Mode::Decipher, aez, tweaks, buffer);
    } else {
        cipher_aez_core(Mode::Decipher, aez, tweaks, buffer);
    }
}

fn cipher_aez_tiny(mode: Mode, aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    let mu = message.len() * 8;
    assert!(mu < 256);
    let n = mu / 2;
    let delta = aez_hash(aez, tweaks);
    let round_count = match mu {
        8 => 24u32,
        16 => 16,
        _ if mu < 128 => 10,
        _ => 8,
    };

    if mode == Mode::Decipher && mu < 128 {
        let mut c = Block::from_slice(message);
        c = c ^ (e(0, 3, aez, delta ^ (c | Block::one())) & Block::one());
        message.copy_from_slice(&c.bytes()[..mu / 8]);
    }

    let (mut left, mut right);
    // We might end up having to split at a nibble, so manually adjust for that
    if n % 8 == 0 {
        left = Block::from_slice(&message[..n / 8]);
        right = Block::from_slice(&message[n / 8..]);
    } else {
        assert!(n % 8 == 4);
        left = Block::from_slice(&message[..n / 8 + 1]).clip(n);
        right = Block::from_slice(&message[n / 8..]) << 4;
    };

    let i = if mu >= 128 { 6 } else { 7 };

    if mode == Mode::Encipher {
        for j in 0..round_count {
            let right_ = (left ^ e(0, i, aez, delta ^ right.pad(n) ^ Block::from_int(j))).clip(n);
            (left, right) = (right, right_);
        }
    } else {
        for j in (0..round_count).rev() {
            let right_ = (left ^ e(0, i, aez, delta ^ right.pad(n) ^ Block::from_int(j))).clip(n);
            (left, right) = (right, right_);
        }
    }

    if n % 8 == 0 {
        message[..n / 8].copy_from_slice(&right.bytes()[..n / 8]);
        message[n / 8..].copy_from_slice(&left.bytes()[..n / 8]);
    } else {
        let mut index = n / 8;
        message[..index + 1].copy_from_slice(&right.bytes()[..index + 1]);
        for byte in &left.bytes()[..n / 8 + 1] {
            message[index] |= byte >> 4;
            if index < message.len() - 1 {
                message[index + 1] = (byte & 0x0f) << 4;
            }
            index += 1;
        }
    }

    if mode == Mode::Encipher && mu < 128 {
        let mut c = Block::from_slice(message);
        c = c ^ (e(0, 3, aez, delta ^ (c | Block::one())) & Block::one());
        message.copy_from_slice(&c.bytes()[..mu / 8]);
    }
}

fn cipher_aez_core(mode: Mode, aez: &Aez, tweaks: Tweak, message: &mut [u8]) {
    assert!(message.len() >= 32);
    let delta = aez_hash(aez, tweaks);
    let mut blocks = BlockAccessor::new(message);
    let (m_u, m_v, m_x, m_y, d) = (
        blocks.m_u(),
        blocks.m_v(),
        blocks.m_x(),
        blocks.m_y(),
        blocks.m_uv_len(),
    );
    let len_v = d.saturating_sub(128);

    let mut x = Block::null();
    let mut e1_eval = E::new(1, 0, aez);
    let e0_eval = E::new(0, 0, aez);

    for (raw_mi, raw_mi_) in blocks.pairs_mut() {
        e1_eval.advance();
        let mi = Block::from(*raw_mi);
        let mi_ = Block::from(*raw_mi_);
        let wi = mi ^ e1_eval.eval(mi_);
        let xi = mi_ ^ e0_eval.eval(wi);

        wi.write_to(raw_mi);
        xi.write_to(raw_mi_);

        x = x ^ xi;
    }

    match d {
        0 => (),
        _ if d <= 127 => {
            x = x ^ e(0, 4, aez, m_u.pad(d));
        }
        _ => {
            x = x ^ e(0, 4, aez, m_u);
            x = x ^ e(0, 5, aez, m_v.pad(len_v));
        }
    }

    let (s_x, s_y);
    match mode {
        Mode::Encipher => {
            s_x = m_x ^ delta ^ x ^ e(0, 1, aez, m_y);
            s_y = m_y ^ e(-1, 1, aez, s_x);
        }
        Mode::Decipher => {
            s_x = m_x ^ delta ^ x ^ e(0, 2, aez, m_y);
            s_y = m_y ^ e(-1, 2, aez, s_x);
        }
    }
    let s = s_x ^ s_y;

    let mut y = Block::null();
    let mut e2_eval = E::new(2, 0, aez);
    let mut e1_eval = E::new(1, 0, aez);
    for (raw_wi, raw_xi) in blocks.pairs_mut() {
        e2_eval.advance();
        e1_eval.advance();
        let wi = Block::from(*raw_wi);
        let xi = Block::from(*raw_xi);
        let s_ = e2_eval.eval(s);
        let yi = wi ^ s_;
        let zi = xi ^ s_;
        let ci_ = yi ^ e0_eval.eval(zi);
        let ci = zi ^ e1_eval.eval(ci_);

        ci.write_to(raw_wi);
        ci_.write_to(raw_xi);

        y = y ^ yi;
    }

    let mut c_u = Block::default();
    let mut c_v = Block::default();

    match d {
        0 => (),
        _ if d <= 127 => {
            c_u = (m_u ^ e(-1, 4, aez, s)).clip(d);
            y = y ^ e(0, 4, aez, c_u.pad(d));
        }
        _ => {
            c_u = m_u ^ e(-1, 4, aez, s);
            c_v = (m_v ^ e(-1, 5, aez, s)).clip(len_v);
            y = y ^ e(0, 4, aez, c_u);
            y = y ^ e(0, 5, aez, c_v.pad(len_v));
        }
    }

    let (c_x, c_y);
    match mode {
        Mode::Encipher => {
            c_y = s_x ^ e(-1, 2, aez, s_y);
            c_x = s_y ^ delta ^ y ^ e(0, 2, aez, c_y);
        }
        Mode::Decipher => {
            c_y = s_x ^ e(-1, 1, aez, s_y);
            c_x = s_y ^ delta ^ y ^ e(0, 1, aez, c_y);
        }
    }

    blocks.set_m_u(c_u);
    blocks.set_m_v(c_v);
    blocks.set_m_x(c_x);
    blocks.set_m_y(c_y);
}

fn pad_to_blocks(value: &[u8]) -> impl Iterator<Item = Block> + '_ {
    value.chunks(16).map(|chunk| {
        if chunk.len() == 16 {
            Block::from_slice(chunk)
        } else {
            Block::from_slice(chunk).pad(chunk.len() * 8)
        }
    })
}

fn aez_hash(aez: &Aez, tweaks: Tweak) -> Block {
    let mut hash = Block::null();
    for (i, tweak) in tweaks.iter().enumerate() {
        // Adjust for zero-based vs one-based indexing
        let j = i + 2 + 1;
        let mut ej = E::new(j.try_into().unwrap(), 0, aez);
        // This is somewhat implicit in the AEZ spec, but basically for an empty string we still
        // set l = 1 and then xor E_K^{j, 0}(10*). We could modify the last if branch to cover this
        // as well, but then we need to fiddle with getting an empty chunk from an empty iterator.
        if tweak.is_empty() {
            hash = hash ^ ej.eval(Block::one());
        } else if tweak.len() % 16 == 0 {
            for chunk in tweak.chunks(16) {
                ej.advance();
                hash = hash ^ ej.eval(Block::from_slice(chunk));
            }
        } else {
            let blocks = pad_to_blocks(tweak);
            for (l, chunk) in blocks.enumerate() {
                ej.advance();
                if l == tweak.len() / 16 {
                    hash = hash ^ e(j.try_into().unwrap(), 0, aez, chunk);
                } else {
                    hash = hash ^ ej.eval(chunk);
                }
            }
        }
    }
    hash
}

/// XOR's the result of aez_prf into the given buffer
fn aez_prf(aez: &Aez, tweaks: Tweak, buffer: &mut [u8]) {
    let mut index = 0u128;
    let delta = aez_hash(aez, tweaks);
    for chunk in buffer.chunks_exact_mut(16) {
        let chunk: &mut [u8; 16] = chunk.try_into().unwrap();
        let block = e(-1, 3, aez, delta ^ Block::from_int(index));
        (block ^ Block::from(*chunk)).write_to(chunk);
        index += 1;
    }
    let suffix_start = buffer.len() - buffer.len() % 16;
    let chunk = &mut buffer[suffix_start..];
    let block = e(-1, 3, aez, delta ^ Block::from_int(index));
    for (a, b) in chunk.iter_mut().zip(block.bytes().iter()) {
        *a ^= *b;
    }
}

/// Represents a computation of E_K^{j,i}.
///
/// As we usually need multiple values with a fixed j and ascending i, this struct saves the
/// temporary values and makes it much faster to compute E_K^{j, i+1}, E_K^{j, i+2}, ...
struct E<'a> {
    aez: &'a Aez,
    i: u32,
    kj_t_j: Block,
    ki_p_i: Block,
}

impl<'a> E<'a> {
    /// Create a new "suspended" computation of E_K^{j,i}.
    fn new(j: i32, i: u32, aez: &'a Aez) -> Self {
        assert!(j >= 0);
        let j: u32 = j.try_into().expect("j was negative");
        let exponent = if i % 8 == 0 { i / 8 } else { i / 8 + 1 };
        E {
            aez,
            i,
            kj_t_j: aez.key_j * j,
            ki_p_i: aez.key_i.exp(exponent),
        }
    }

    /// Complete this computation to evaluate E_K^{j,i}(block).
    fn eval(&self, block: Block) -> Block {
        let delta = self.kj_t_j ^ self.ki_p_i ^ self.aez.key_l_multiples[self.i as usize % 8];
        self.aez.aes.aes4(block ^ delta)
    }

    /// Advance this computation by going from i to i+1.
    ///
    /// Afterwards, this computation will represent E_K^{j, i+1}
    fn advance(&mut self) {
        // We need to advance ki_p_i if exponent = old_exponent + 1
        // This happens exactly when the old exponent was just a multiple of 8, because the
        // next exponent is then not a multiple anymore and will be rounded *up*.
        if self.i % 8 == 0 {
            self.ki_p_i = self.ki_p_i * 2
        };
        self.i += 1;
    }
}

/// Shorthand to get E_K^{j,i}(block)
fn e(j: i32, i: u32, aez: &Aez, block: Block) -> Block {
    if j == -1 {
        let delta = if i < 8 {
            aez.key_l_multiples[i as usize]
        } else {
            aez.key_l * i
        };
        aez.aes.aes10(block ^ delta)
    } else {
        E::new(j, i, aez).eval(block)
    }
}

fn split_key(key: &[u8; 48]) -> (Block, Block, Block) {
    (
        Block::from_slice(&key[..16]),
        Block::from_slice(&key[16..32]),
        Block::from_slice(&key[32..]),
    )
}

#[cfg(test)]
mod test {
    use super::*;

    /// Local hex decoder, so the vendored tests need no `hex` dev dependency.
    fn hx(text: &str) -> Vec<u8> {
        assert!(text.len() % 2 == 0, "odd hex length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn test_extract() {
        for (a, b) in testvectors::EXTRACT_VECTORS {
            let a = hx(a);
            let b = hx(b);
            assert_eq!(extract(&a), b.as_slice());
        }
    }

    #[test]
    fn test_e() {
        for (k, j, i, a, b) in testvectors::E_VECTORS {
            let name = format!("e({j}, {i}, {k}, {a})");
            let k = hx(k);
            let aez = Aez::new(k.as_slice());
            let a = hx(a);
            let a = Block::from_slice(&a);
            let b = hx(b);
            assert_eq!(&e(*j, *i, &aez, a).bytes(), b.as_slice(), "{name}");
        }
    }

    #[test]
    fn test_aez_hash() {
        for (k, tau, tw, v) in testvectors::HASH_VECTORS {
            let name = format!("aez_hash({k}, {tau}, {tw:?})");
            let k = hx(k);
            let aez = Aez::new(k.as_slice());
            let v = hx(v);

            let mut tweaks = vec![Vec::from(Block::from_int(*tau).bytes())];
            for t in *tw {
                tweaks.push(hx(t));
            }
            let tweaks = tweaks.iter().map(Vec::as_slice).collect::<Vec<_>>();

            assert_eq!(&aez_hash(&aez, &tweaks).bytes(), v.as_slice(), "{name}");
        }
    }

    fn vec_encrypt(key: &Key, nonce: &[u8], ad: &[&[u8]], tau: u32, message: &[u8]) -> Vec<u8> {
        let aez = Aez::new(key);
        let mut v = vec![0; message.len() + tau as usize];
        v[..message.len()].copy_from_slice(message);
        encrypt(&aez, nonce, ad, tau, &mut v);
        v
    }

    fn vec_decrypt(
        key: &Key,
        nonce: &[u8],
        ad: &[&[u8]],
        tau: u32,
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        let aez = Aez::new(key);
        let mut v = Vec::from(ciphertext);
        let len = match decrypt(&aez, nonce, ad, tau, &mut v) {
            None => return None,
            Some(m) => m.len(),
        };
        v.truncate(len);
        Some(v)
    }

    #[test]
    fn test_encrypt() {
        let mut failed = 0;
        for (k, n, ads, tau, m, c) in testvectors::ENCRYPT_VECTORS {
            let name = format!("encrypt({k}, {n}, {ads:?}, {tau}, {m})");
            let k = hx(k);
            let k = k.as_slice().try_into().unwrap();
            let n = hx(n);

            let mut ad = Vec::new();
            for i in *ads {
                ad.push(hx(i));
            }
            let ad = ad.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let m = hx(m);
            let c = hx(c);

            if vec_encrypt(&k, &n, &ad, *tau, &m) != c {
                println!("- {name}");
                failed += 1;
            }
        }
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_decrypt() {
        let mut failed = 0;
        for (k, n, ads, tau, m, c) in testvectors::ENCRYPT_VECTORS {
            let name = format!("decrypt({k}, {n}, {ads:?}, {tau}, {c})");
            let k = hx(k);
            let k = k.as_slice().try_into().unwrap();
            let n = hx(n);

            let mut ad = Vec::new();
            for i in *ads {
                ad.push(hx(i));
            }
            let ad = ad.iter().map(Vec::as_slice).collect::<Vec<_>>();

            let m = hx(m);
            let c = hx(c);

            if vec_decrypt(&k, &n, &ad, *tau, &c) != Some(m) {
                println!("- {name}");
                failed += 1;
            }
        }
        assert_eq!(failed, 0);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let aez = Aez::new(b"foobar");
        let mut cipher = vec![0u8; 2 + 16];
        cipher[..2].copy_from_slice(b"hi");
        encrypt(&aez, &[0], &[b"foobar"], 16, &mut cipher);
        let plain = aez.decrypt(&[0], &[b"foobar"], 16, &cipher).unwrap();
        assert_eq!(plain, b"hi");
    }
}
