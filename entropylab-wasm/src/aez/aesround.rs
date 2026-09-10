// Part of the vendored AEZ v5 module; see mod.rs for provenance and license.
// From zears 0.2.1 src/aesround.rs with the x86_64 AES-NI module removed: its
// unconditional `cpufeatures` dependency does not compile on
// wasm32-unknown-unknown, and the software path below is the one every
// non-x86_64 build of that crate uses anyway.

use super::block::Block;

pub type AesImpl = AesSoft;

pub trait AesRound {
    fn new(key_i: Block, key_j: Block, key_l: Block) -> Self;
    fn aes4(&self, value: Block) -> Block;
    fn aes10(&self, value: Block) -> Block;
}

/// Implementation of aes4 and aes10 in software.
///
/// Always available.
///
/// Uses the `aes` crate under the hood.
pub struct AesSoft {
    key_i: aes::Block,
    key_j: aes::Block,
    key_l: aes::Block,
}

impl AesRound for AesSoft {
    fn new(key_i: Block, key_j: Block, key_l: Block) -> Self {
        Self {
            key_i: key_i.bytes().into(),
            key_j: key_j.bytes().into(),
            key_l: key_l.bytes().into(),
        }
    }

    fn aes4(&self, value: Block) -> Block {
        let mut block: aes::Block = value.bytes().into();
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &Block::null().bytes().into());
        <Block as From<[u8; 16]>>::from(block.into())
    }

    fn aes10(&self, value: Block) -> Block {
        let mut block: aes::Block = value.bytes().into();
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        ::aes::hazmat::cipher_round(&mut block, &self.key_j);
        ::aes::hazmat::cipher_round(&mut block, &self.key_l);
        ::aes::hazmat::cipher_round(&mut block, &self.key_i);
        <Block as From<[u8; 16]>>::from(block.into())
    }
}
