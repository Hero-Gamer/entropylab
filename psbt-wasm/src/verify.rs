//! Consensus-level problem analysis for a parsed PSBT: the layer every edit
//! is checked against unless insane editing is on. Structural BIP-174
//! validity is enforced by the parser itself; this module answers the harder
//! question — could the transaction these maps describe ever be valid, and do
//! the signatures and UTXO claims in them hold up?
//!
//! Two severities:
//!   error   — a consensus rule or a BIP-174 signer check is violated: the
//!             build gate refuses the edit (insane editing bypasses it).
//!   warning — suspicious but not provably invalid: partial signatures that
//!             do not verify (a signing round in progress), missing UTXO
//!             declarations BIP-174 only recommends, non-standard sighashes.
//!
//! Verification needs the spent outputs, and the only source a PSBT has is
//! its own UTXO declarations — so every verdict here is "against the claimed
//! previous output". What can be checked without a claim is (a witness
//! script hashing to the claimed program, a Taproot control block proving
//! its script under the claimed output key).

use bitcoin::blockdata::script::{Instruction, Script};
use bitcoin::consensus::{encode, Decodable};
use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, TapLeafHash};
use bitcoin::{ScriptBuf, Transaction, TxOut, Witness};

use crate::{hex_encode, pair_utxo_claim, tx_sanity_error, RawPair};

pub(crate) const ERROR: &str = "error";
pub(crate) const WARNING: &str = "warning";

// Signature verification is the only superlinear work here (a legacy sighash
// re-serializes the transaction), and the inspector accepts up to 100k
// inputs. Past this many verifications in one analysis the remaining
// signatures are reported unchecked instead — the same budgeted shape the
// sanitize pass uses (a 5 MB hostile PSBT must not freeze the editor).
const MAX_SIGNATURE_CHECKS: usize = 256;

/// The verification budget: `take()` returns false once exhausted, and the
/// caller notes the exhaustion in the problem list exactly once.
struct Budget {
    left: usize,
    noted: bool,
}

impl Budget {
    fn take(&mut self, problems: &mut Vec<Problem>) -> bool {
        if self.left > 0 {
            self.left -= 1;
            return true;
        }
        if !self.noted {
            self.noted = true;
            // Error severity: past the budget the document is not fully
            // vouched, and a gate that cannot check must fail closed (insane
            // editing is the bypass), never wave the rest through.
            problems.push(Problem::error(
                "transaction".into(),
                "verification_budget",
                format!("verification budget exhausted after {MAX_SIGNATURE_CHECKS} signatures — later signatures are unchecked"),
            ));
        }
        false
    }
}

#[derive(Debug)]
pub(crate) struct Problem {
    pub(crate) severity: &'static str,
    pub(crate) scope: String,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl Problem {
    pub(crate) fn error(scope: String, code: &'static str, message: impl Into<String>) -> Self {
        Problem { severity: ERROR, scope, code, message: message.into() }
    }
    pub(crate) fn warning(scope: String, code: &'static str, message: impl Into<String>) -> Self {
        Problem { severity: WARNING, scope, code, message: message.into() }
    }
}

/// How an input's spend will be authorized, from the claimed scriptPubKey
/// plus the input map's redeem/witness scripts. `Unknown` means the claim is
/// missing or P2SH without its redeem script — nothing can be asserted then.
enum Spend {
    P2wpkh,
    P2wsh(Option<ScriptBuf>),
    P2tr(XOnlyPublicKey),
    WrappedP2wpkh(ScriptBuf),
    WrappedP2wsh(ScriptBuf, Option<ScriptBuf>),
    /// P2SH whose redeem script is not a witness program.
    LegacyP2sh(ScriptBuf),
    /// The claimed scriptPubKey itself is the script being signed.
    Legacy,
    /// A witness program of a version this crate does not know (v2+): segwit
    /// for the UTXO-declaration checks, unverifiable for signatures.
    UnknownWitness,
    Unknown,
}

impl Spend {
    fn is_witness(&self) -> bool {
        matches!(
            self,
            Spend::P2wpkh | Spend::P2wsh(_) | Spend::P2tr(_) | Spend::WrappedP2wpkh(_) | Spend::WrappedP2wsh(..) | Spend::UnknownWitness
        )
    }
}

/// The single pair of a keyless-data type in an input map, when exactly one
/// exists. (Duplicate keys are a format error caught before analysis.)
fn input_field<'a>(map: &'a [RawPair], type_byte: u8) -> Option<&'a [u8]> {
    map.iter()
        .find(|pair| pair.key.as_slice() == [type_byte])
        .map(|pair| pair.value.as_slice())
}

/// The input map's witness script (0x05), hash-checked against the program it
/// must match: the claim's own program for native P2WSH, the redeem script's
/// for the wrapped form (BIP-174 signer checks).
fn checked_witness_script(
    map: &[RawPair],
    program: &[u8],
    scope: &str,
    problems: &mut Vec<Problem>,
) -> Option<ScriptBuf> {
    let value = input_field(map, 0x05)?;
    if sha256::Hash::hash(value).to_byte_array()[..] != program[..] {
        problems.push(Problem::error(
            scope.into(),
            "witness_script_mismatch",
            "witnessScript does not hash to the claimed output's witness program",
        ));
        return None;
    }
    Some(ScriptBuf::from_bytes(value.to_vec()))
}

/// Classifies one input's spend from its claim and script pairs, reporting
/// the BIP-174 signer checks that fail along the way (redeem/witness script
/// hash mismatches).
fn classify(index: usize, map: &[RawPair], claim: &TxOut, problems: &mut Vec<Problem>) -> Spend {
    let scope = format!("input {index}");
    let script = claim.script_pubkey.as_script();
    if script.is_p2wpkh() {
        return Spend::P2wpkh;
    }
    if script.is_p2wsh() {
        let ws = checked_witness_script(map, &script.as_bytes()[2..], &scope, problems);
        return Spend::P2wsh(ws);
    }
    if script.is_p2tr() {
        return match XOnlyPublicKey::from_slice(&script.as_bytes()[2..]) {
            Ok(key) => Spend::P2tr(key),
            Err(_) => Spend::Unknown, // 32 bytes that are not a liftable key
        };
    }
    if script.is_witness_program() {
        return Spend::UnknownWitness; // a future witness version
    }
    if script.is_p2sh() {
        let Some(redeem) = input_field(map, 0x04) else { return Spend::Unknown };
        if hash160::Hash::hash(redeem).to_byte_array()[..] != script.as_bytes()[2..22] {
            problems.push(Problem::error(
                scope,
                "redeem_script_mismatch",
                "redeemScript does not hash to the claimed output's P2SH scriptPubKey",
            ));
            return Spend::Unknown;
        }
        let redeem = ScriptBuf::from_bytes(redeem.to_vec());
        if redeem.is_p2wpkh() {
            return Spend::WrappedP2wpkh(redeem);
        }
        if redeem.is_p2wsh() {
            let ws = checked_witness_script(map, &redeem.as_bytes()[2..], &scope, problems);
            return Spend::WrappedP2wsh(redeem, ws);
        }
        return Spend::LegacyP2sh(redeem);
    }
    Spend::Legacy
}

/// The legacy scriptCode with OP_CODESEPARATOR opcodes removed, the way
/// Bitcoin Core's SignatureHash serializes it
/// (CTransactionSignatureSerializer::SerializeScriptCode). Pushed data is
/// copied verbatim, separators inside it included. A truncated push ends the
/// walk; Core's preimage differs in that case, but a script with a truncated
/// push fails EvalScript, so no signature over it is ever valid.
/// rust-bitcoin's legacy_signature_hash documents that it does NOT attempt
/// to support OP_CODESEPARATOR, so the stripping happens here.
///
/// The verifier does not execute scripts, so a separator that would execute
/// before the signature's CHECKSIG is stripped too, where Core hashes only
/// the suffix after the last executed separator. For those scripts the
/// verdict can still differ from Core; that is a property of verifying
/// without execution, not of this function.
fn strip_codeseparators(script: &[u8]) -> Vec<u8> {
    const OP_CODESEPARATOR: u8 = 0xab;
    let mut out = Vec::with_capacity(script.len());
    let mut pc = 0;
    while pc < script.len() {
        let op = script[pc];
        let (data_len, header) = match op {
            0x01..=0x4b => (op as usize, 1),
            0x4c if pc + 2 <= script.len() => (script[pc + 1] as usize, 2),
            0x4d if pc + 3 <= script.len() => (u16::from_le_bytes([script[pc + 1], script[pc + 2]]) as usize, 3),
            0x4e if pc + 5 <= script.len() => (u32::from_le_bytes(script[pc + 1..pc + 5].try_into().unwrap()) as usize, 5),
            0x4c | 0x4d | 0x4e => break, // truncated PUSHDATA header
            _ => (0, 1),
        };
        // Compare against the bytes left instead of summing: on wasm32 a
        // PUSHDATA4 length near 2^32 would wrap pc + header + data_len and
        // hang or trap the module. The guards above give pc + header <= len.
        if data_len > script.len() - pc - header {
            break; // truncated push
        }
        let end = pc + header + data_len;
        if op != OP_CODESEPARATOR {
            out.extend_from_slice(&script[pc..end]);
        }
        pc = end;
    }
    out
}

/// The BIP-143 or legacy sighash one ECDSA signature commits to, by spend
/// kind. `script_code`/`amount` come from the claim (or the redeem/witness
/// script inside it). None when the sighash cannot be computed (a P2WSH spend
/// without its witness script, SIGHASH_SINGLE past the outputs).
fn ecdsa_sighash(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    spend: &Spend,
    claim: &TxOut,
    sighash_type: EcdsaSighashType,
) -> Option<[u8; 32]> {
    let value = claim.value;
    let hash = match spend {
        Spend::P2wpkh => cache.p2wpkh_signature_hash(index, &claim.script_pubkey, value, sighash_type).ok()?.to_byte_array(),
        Spend::WrappedP2wpkh(redeem) => cache.p2wpkh_signature_hash(index, redeem, value, sighash_type).ok()?.to_byte_array(),
        Spend::P2wsh(Some(ws)) => cache.p2wsh_signature_hash(index, ws, value, sighash_type).ok()?.to_byte_array(),
        Spend::WrappedP2wsh(_, Some(ws)) => cache.p2wsh_signature_hash(index, ws, value, sighash_type).ok()?.to_byte_array(),
        Spend::P2wsh(None) | Spend::WrappedP2wsh(_, None) => return None,
        Spend::LegacyP2sh(redeem) => cache.legacy_signature_hash(index, Script::from_bytes(&strip_codeseparators(redeem.as_bytes())), sighash_type.to_u32()).ok()?.to_byte_array(),
        Spend::Legacy => cache.legacy_signature_hash(index, Script::from_bytes(&strip_codeseparators(claim.script_pubkey.as_bytes())), sighash_type.to_u32()).ok()?.to_byte_array(),
        // Taproot inputs sign with Schnorr; an ECDSA partial signature there
        // is reported by the caller instead of hashed. Future witness
        // versions have no sighash here yet.
        Spend::P2tr(_) | Spend::Unknown | Spend::UnknownWitness => return None,
    };
    Some(hash)
}

/// Verifies one DER-encoded ECDSA signature plus sighash byte against the
/// spend's digest. Returns the verdict text on failure; None when it
/// verifies or cannot be computed (uncomputable is reported separately).
fn check_ecdsa(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    spend: &Spend,
    claim: &TxOut,
    pubkey: &[u8],
    sig: &[u8],
) -> Option<Result<(), String>> {
    let (&sighash_byte, der) = sig.split_last()?;
    let sighash_type = EcdsaSighashType::from_consensus(sighash_byte as u32);
    let digest = ecdsa_sighash(cache, index, spend, claim, sighash_type)?;
    let pubkey = match PublicKey::from_slice(pubkey) {
        Ok(key) => key,
        Err(_) => return Some(Err("public key is not a valid secp256k1 key".into())),
    };
    let signature = match secp256k1::ecdsa::Signature::from_der(der) {
        Ok(sig) => sig,
        Err(_) => return Some(Err("signature is not valid DER".into())),
    };
    let message = Message::from_digest_slice(&digest).expect("a sighash is 32 bytes");
    Some(
        Secp256k1::verification_only()
            .verify_ecdsa(&message, &signature, &pubkey)
            .map_err(|_| "signature does not verify against the claimed previous output".into()),
    )
}

/// BIP-341 sighash for a taproot input. Every input needs a resolved claim —
/// the digest commits to all of them — so a partial claim set makes every
/// taproot signature unverifiable (the caller then stays silent: an
/// unverifiable signature is not an invalid one).
fn taproot_sighash_key_spend(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    prevouts: &Option<Vec<TxOut>>,
    sighash_type: TapSighashType,
) -> Option<[u8; 32]> {
    let prevouts = prevouts.as_ref()?;
    cache
        .taproot_key_spend_signature_hash(index, &Prevouts::All(prevouts), sighash_type)
        .ok()
        .map(|h| h.to_byte_array())
}

fn taproot_sighash_script_spend(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    prevouts: &Option<Vec<TxOut>>,
    leaf_hash: &[u8],
    sighash_type: TapSighashType,
) -> Option<[u8; 32]> {
    let prevouts = prevouts.as_ref()?;
    let leaf_hash = TapLeafHash::from_slice(leaf_hash).ok()?;
    cache
        .taproot_script_spend_signature_hash(index, &Prevouts::All(prevouts), leaf_hash, sighash_type)
        .ok()
        .map(|h| h.to_byte_array())
}

/// Parses a 64/65-byte BIP-340 signature into (signature, sighash type);
/// the message names what is being read for the verdict text.
fn read_tap_sig(value: &[u8], what: &str) -> Result<(secp256k1::schnorr::Signature, TapSighashType), String> {
    let (raw, sighash_byte) = match value.len() {
        64 => (value, 0u8),
        65 => (&value[..64], value[64]),
        _ => return Err(format!("{what} must be 64 or 65 bytes")),
    };
    let signature =
        secp256k1::schnorr::Signature::from_slice(raw).map_err(|_| format!("{what} is not a valid Schnorr signature"))?;
    let sighash_type = TapSighashType::from_consensus_u8(sighash_byte)
        .map_err(|_| format!("{what} uses invalid taproot sighash type 0x{sighash_byte:02x}"))?;
    Ok((signature, sighash_type))
}

fn check_schnorr(digest: [u8; 32], signature: &secp256k1::schnorr::Signature, key: &XOnlyPublicKey) -> Result<(), String> {
    let message = Message::from_digest_slice(&digest).expect("a sighash is 32 bytes");
    Secp256k1::verification_only()
        .verify_schnorr(signature, &message, key)
        .map_err(|_| "signature does not verify against the claimed previous output".into())
}

/// Partial signatures (0x02): verified when the spend is classifiable and the
/// sighash computable. Invalid partials are warnings, not gate errors — a
/// PSBT mid-signing-round is a normal object, and a wrong partial signature
/// is the signer's problem, not the format's. A Taproot input carrying
/// ECDSA partials is the oddity worth naming.
fn check_partial_sigs(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    map: &[RawPair],
    spend: &Spend,
    claim: &TxOut,
    sighash_field: Option<u32>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
) {
    let scope = format!("input {index}");
    for pair in map.iter().filter(|pair| pair.key[0] == 0x02) {
        let pubkey = &pair.key[1..];
        let short = &hex_encode(pubkey);
        let short = &short[..short.len().min(16)];
        if matches!(spend, Spend::P2tr(_)) {
            problems.push(Problem::warning(
                scope.clone(),
                "partial_sig_on_taproot",
                format!("ECDSA partial signature (pubkey {short}…) on a taproot input, which signs with Schnorr"),
            ));
            continue;
        }
        if let Some(&byte) = pair.value.last() {
            if EcdsaSighashType::from_standard(byte as u32).is_err() {
                problems.push(Problem::warning(
                    scope.clone(),
                    "sighash_nonstandard",
                    format!("partial signature (pubkey {short}…) uses non-standard sighash type 0x{byte:02x}"),
                ));
            }
            if sighash_field.is_some_and(|declared| declared != byte as u32) {
                problems.push(Problem::warning(
                    scope.clone(),
                    "sighash_mismatch",
                    format!("partial signature (pubkey {short}…) sighash byte disagrees with PSBT_IN_SIGHASH_TYPE"),
                ));
            }
        }
        if !budget.take(problems) {
            continue;
        }
        match check_ecdsa(cache, index, spend, claim, pubkey, &pair.value) {
            Some(Ok(())) => {}
            Some(Err(why)) => problems.push(Problem::warning(
                scope.clone(),
                "partial_sig_invalid",
                format!("partial signature (pubkey {short}…) {why}"),
            )),
            None => {} // no sighash without a witness script; nothing to claim
        }
    }
}

/// Taproot signatures: the key-spend signature (0x13) against the claimed
/// output key, and script-path signatures (0x14) against their xonly key and
/// leaf hash. Warnings, like ECDSA partials.
fn check_tap_sigs(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    map: &[RawPair],
    spend: &Spend,
    prevouts: &Option<Vec<TxOut>>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
) {
    let Spend::P2tr(output_key) = spend else { return };
    let scope = format!("input {index}");
    if let Some(value) = input_field(map, 0x13) {
        match read_tap_sig(value, "key-path signature") {
            Err(why) => problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", why)),
            Ok((sig, ty)) if !budget.take(problems) => {
                let _ = (sig, ty);
            }
            Ok((sig, ty)) => match taproot_sighash_key_spend(cache, index, prevouts, ty) {
                None => {} // prevout set incomplete: cannot compute, cannot accuse
                Some(digest) => {
                    if let Err(why) = check_schnorr(digest, &sig, output_key) {
                        problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", format!("key-path {why}")));
                    }
                }
            },
        }
    }
    for pair in map.iter().filter(|pair| pair.key[0] == 0x14 && pair.key.len() == 65) {
        let xonly = &pair.key[1..33];
        let leaf_hash = &pair.key[33..65];
        let short = &hex_encode(xonly)[..16];
        let Ok(key) = XOnlyPublicKey::from_slice(xonly) else {
            problems.push(Problem::warning(
                scope.clone(),
                "tap_sig_invalid",
                format!("script-path signature (xonly {short}…) has an invalid public key"),
            ));
            continue;
        };
        if !budget.take(problems) {
            continue;
        }
        match read_tap_sig(&pair.value, "script-path signature") {
            Err(why) => problems.push(Problem::warning(scope.clone(), "tap_sig_invalid", why)),
            Ok((sig, ty)) => match taproot_sighash_script_spend(cache, index, prevouts, leaf_hash, ty) {
                None => {}
                Some(digest) => {
                    if let Err(why) = check_schnorr(digest, &sig, &key) {
                        problems.push(Problem::warning(
                            scope.clone(),
                            "tap_sig_invalid",
                            format!("script-path signature (xonly {short}…) {why}"),
                        ));
                    }
                }
            },
        }
    }
}

/// The pushes of a final scriptSig; None when the script is not push-only or
/// does not parse. The small-number opcodes are pushes (of the empty vector
/// for OP_0, of the number for OP_1..OP_16) — a P2SH multisig scriptSig
/// starts with OP_0, as CHECKMULTISIG's stack dummy.
fn script_pushes(script: &Script) -> Option<Vec<Vec<u8>>> {
    use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16};
    use bitcoin::opcodes::OP_0;
    let mut pushes = Vec::new();
    for instruction in script.instructions_minimal() {
        match instruction {
            Ok(Instruction::PushBytes(bytes)) => pushes.push(bytes.as_bytes().to_vec()),
            Ok(Instruction::Op(op)) if op == OP_0 => pushes.push(Vec::new()),
            Ok(Instruction::Op(op)) if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_16.to_u8() => {
                pushes.push(vec![op.to_u8() - OP_PUSHNUM_1.to_u8() + 1]);
            }
            _ => return None,
        }
    }
    Some(pushes)
}

/// Final scriptSig (0x07): for a P2PKH claim it must be exactly [sig,
/// pubkey], the pubkey must hash to the claim, and the signature must verify
/// — a finalized input is the claim "this is the spending transaction", so a
/// failure here is a consensus-invalid spend, an error. For P2SH the last
/// push must be the redeem script (hash-checked); a wrapped-segwit redeem
/// script then requires the final witness, which is checked separately.
fn check_final_scriptsig(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    value: &[u8],
    spend: &Spend,
    claim: &TxOut,
    has_final_witness: bool,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
) {
    let scope = format!("input {index}");
    let script = Script::from_bytes(value);
    let claim_script = claim.script_pubkey.as_script();
    if claim_script.is_p2sh() {
        let Spend::LegacyP2sh(redeem) = spend else {
            // Wrapped segwit: scriptSig must push exactly the redeem script,
            // and the input then needs its final witness.
            let wrapped = matches!(spend, Spend::WrappedP2wpkh(_) | Spend::WrappedP2wsh(..));
            if wrapped {
                let ok = script_pushes(script).is_some_and(|p| p.len() == 1 && matches!(spend, Spend::WrappedP2wpkh(r) | Spend::WrappedP2wsh(r, _) if p[0] == *r.as_bytes()));
                if !ok {
                    problems.push(Problem::error(
                        scope.clone(),
                        "final_scriptsig_bad",
                        "final scriptSig of a wrapped-segwit input must push exactly its redeemScript",
                    ));
                }
                if !has_final_witness {
                    problems.push(Problem::error(
                        scope,
                        "final_witness_bad",
                        "wrapped-segwit input has a final scriptSig but no final witness",
                    ));
                }
            }
            return;
        };
        // Legacy P2SH: the last push is the redeem script (its hash was
        // checked at classification); executing the script is out of scope.
        match script_pushes(script) {
            Some(pushes) if pushes.last().is_some_and(|last| *last == *redeem.as_bytes()) => {}
            _ => problems.push(Problem::error(
                scope,
                "final_scriptsig_bad",
                "final scriptSig's last push is not the input's redeemScript",
            )),
        }
        return;
    }
    if !claim_script.is_p2pkh() {
        return; // bare multisig and friends need an interpreter; structure says nothing
    }
    let Some(pushes) = script_pushes(script) else {
        problems.push(Problem::error(
            scope,
            "final_scriptsig_bad",
            "final scriptSig of a P2PKH input is not push-only",
        ));
        return;
    };
    if pushes.len() != 2 {
        problems.push(Problem::error(
            scope,
            "final_scriptsig_bad",
            "final scriptSig of a P2PKH input must be [signature, public key]",
        ));
        return;
    }
    let [sig, pubkey] = [&pushes[0], &pushes[1]];
    if hash160::Hash::hash(pubkey).to_byte_array()[..] != claim_script.as_bytes()[3..23] {
        problems.push(Problem::error(
            scope.clone(),
            "final_scriptsig_bad",
            "final scriptSig public key does not hash to the claimed output's key hash",
        ));
        return;
    }
    if !budget.take(problems) {
        return;
    }
    match check_ecdsa(cache, index, &Spend::Legacy, claim, pubkey, sig) {
        Some(Ok(())) => {}
        Some(Err(why)) => problems.push(Problem::error(scope, "final_scriptsig_bad", format!("final scriptSig {why}"))),
        None => problems.push(Problem::error(scope, "final_scriptsig_bad", "final scriptSig sighash cannot be computed")),
    }
}

/// Final witness (0x08): structure and signature against the claim. P2WPKH is
/// exactly [sig, pubkey] with the pubkey hashing to the program; P2WSH's last
/// item must hash to the program (and equal the declared witnessScript);
/// P2TR is a single key-path signature or a script-path stack whose control
/// block must prove its script under the claimed output key. A final witness
/// spending a proven non-witness output is only a warning (consensus never
/// reads it; policy does).
fn check_final_witness(
    cache: &mut SighashCache<&Transaction>,
    index: usize,
    witness: &Witness,
    spend: &Spend,
    claim: &TxOut,
    prevouts: &Option<Vec<TxOut>>,
    budget: &mut Budget,
    problems: &mut Vec<Problem>,
) {
    let scope = format!("input {index}");
    let items: Vec<&[u8]> = witness.iter().collect();
    match spend {
        Spend::P2wpkh | Spend::WrappedP2wpkh(_) => {
            let program = &claim.script_pubkey.as_bytes()[2..22];
            if items.len() != 2 {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    format!("P2WPKH final witness must be [signature, public key], got {} item(s)", items.len()),
                ));
                return;
            }
            if items[1].len() != 33 || hash160::Hash::hash(items[1]).to_byte_array()[..] != program[..] {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness public key does not hash to the claimed output's witness program",
                ));
                return;
            }
            if !budget.take(problems) {
                return;
            }
            match check_ecdsa(cache, index, spend, claim, items[1], items[0]) {
                Some(Ok(())) => {}
                Some(Err(why)) => problems.push(Problem::error(scope, "final_witness_bad", format!("final witness {why}"))),
                None => problems.push(Problem::error(scope, "final_witness_bad", "final witness sighash cannot be computed")),
            }
        }
        Spend::P2wsh(declared) | Spend::WrappedP2wsh(_, declared) => {
            let Some((&script_item, _stack)) = items.split_last() else {
                problems.push(Problem::error(scope, "final_witness_bad", "P2WSH final witness is empty"));
                return;
            };
            let program = match spend {
                Spend::P2wsh(_) => &claim.script_pubkey.as_bytes()[2..34],
                Spend::WrappedP2wsh(redeem, _) => &redeem.as_bytes()[2..34],
                _ => unreachable!(),
            };
            if sha256::Hash::hash(script_item).to_byte_array()[..] != program[..] {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness's last item does not hash to the claimed output's witness program",
                ));
                return;
            }
            if declared.as_ref().is_some_and(|ws| ws.as_bytes() != script_item) {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "final witness's script disagrees with the input's witnessScript",
                ));
            }
            // Executing the witness script needs an interpreter, which this
            // crate deliberately does not carry; the hash binding above is
            // the structural part of the check.
        }
        Spend::P2tr(output_key) => {
            // BIP-341: with at least two stack elements, a last element
            // starting with 0x50 is the annex and comes off first.
            let items = if items.len() >= 2 && items.last().is_some_and(|last| !last.is_empty() && last[0] == 0x50) {
                &items[..items.len() - 1]
            } else {
                &items[..]
            };
            if items.len() == 1 {
                match read_tap_sig(items[0], "final key-path signature") {
                    Err(why) => problems.push(Problem::error(scope, "final_witness_bad", why)),
                    Ok((sig, ty)) if !budget.take(problems) => {
                        let _ = (sig, ty);
                    }
                    Ok((sig, ty)) => match taproot_sighash_key_spend(cache, index, prevouts, ty) {
                        Some(digest) => {
                            if let Err(why) = check_schnorr(digest, &sig, output_key) {
                                problems.push(Problem::error(scope, "final_witness_bad", format!("final {why}")));
                            }
                        }
                        None => problems.push(Problem::error(
                            scope,
                            "final_witness_bad",
                            "final key-path signature's sighash cannot be computed from the declared UTXOs",
                        )),
                    },
                }
                return;
            }
            if items.len() < 2 {
                problems.push(Problem::error(scope, "final_witness_bad", "taproot final witness is empty"));
                return;
            }
            let (control, rest) = items.split_last().unwrap();
            let script = Script::from_bytes(rest.last().unwrap());
            let control = match ControlBlock::decode(control) {
                Ok(control) => control,
                Err(_) => {
                    problems.push(Problem::error(scope, "final_witness_bad", "taproot control block does not decode"));
                    return;
                }
            };
            if !control.verify_taproot_commitment(&Secp256k1::verification_only(), *output_key, script) {
                problems.push(Problem::error(
                    scope,
                    "final_witness_bad",
                    "taproot control block does not prove its script under the claimed output key",
                ));
            }
            // Script-path stack execution needs an interpreter; the
            // commitment above is the checkable part.
        }
        // No claim, an unclassifiable one, or a future witness version:
        // nothing to check against.
        Spend::Unknown | Spend::UnknownWitness => {}
        legacy => {
            if !legacy.is_witness() {
                problems.push(Problem::warning(
                    scope,
                    "final_witness_on_legacy",
                    "final witness on an input spending a non-witness output — never read by consensus, non-standard",
                ));
            }
        }
    }
}

/// One input's UTXO declarations resolved to claims, with the disagreements
/// reported as problems. Returns the claim to classify and verify against
/// (None on conflict — no verdict can rest on a disputed output).
fn input_claims(
    tx: &Transaction,
    index: usize,
    map: &[RawPair],
    problems: &mut Vec<Problem>,
) -> (Option<TxOut>, Option<TxOut>) {
    let scope = format!("input {index}");
    let mut witness_claim = None;
    let mut non_witness_claim = None;
    for pair in map {
        match pair.key.as_slice() {
            [0x01] => witness_claim = pair_utxo_claim(pair, tx, index),
            [0x00] => {
                // A non-witness UTXO whose txid is not the input's prevout is
                // not merely useless: BIP-174 makes it an invalid PSBT (the
                // signer's first check fails).
                if let Ok(prev) = Transaction::consensus_decode(&mut &pair.value[..]) {
                    if encode::serialize(&prev) == pair.value {
                        // Callers guarantee one map per transaction input;
                        // stay defensive anyway — this is a gate.
                        let Some(input) = tx.input.get(index) else { continue };
                        if input.previous_output.txid != prev.compute_txid() {
                            problems.push(Problem::error(
                                scope.clone(),
                                "nonwitness_txid_mismatch",
                                "non-witness UTXO's txid does not match the input's prevout — the PSBT is invalid per BIP-174",
                            ));
                        }
                    }
                }
                non_witness_claim = pair_utxo_claim(pair, tx, index);
            }
            _ => {}
        }
    }
    if let (Some(wit), Some(non)) = (&witness_claim, &non_witness_claim) {
        if wit.value != non.value || wit.script_pubkey != non.script_pubkey {
            problems.push(Problem::error(
                scope,
                "utxo_claim_conflict",
                format!(
                    "witness UTXO ({} sats) and non-witness UTXO ({} sats) claim different previous outputs",
                    wit.value.to_sat(),
                    non.value.to_sat()
                ),
            ));
            return (None, None);
        }
    }
    (witness_claim, non_witness_claim)
}

/// Every consensus-level and BIP-174-level problem with the PSBT, as a flat
/// list ordered transaction-first then by input. `prevouts` for taproot
/// sighashes is assembled once from all inputs' claims.
pub(crate) fn analyze(tx: &Transaction, inputs: &[Vec<RawPair>]) -> Vec<Problem> {
    let mut problems = Vec::new();
    if let Some(reason) = tx_sanity_error(tx) {
        problems.push(Problem::error(
            "transaction".into(),
            "tx_consensus",
            format!("unsigned transaction is consensus-invalid: {reason}"),
        ));
    }

    // First pass: claims and their disagreements.
    let claims: Vec<(Option<TxOut>, Option<TxOut>)> = inputs
        .iter()
        .enumerate()
        .map(|(index, map)| input_claims(tx, index, map, &mut problems))
        .collect();

    // The taproot prevout set: every input's claim, or nothing (BIP-341
    // commits to all of them).
    let all_claims: Option<Vec<TxOut>> = claims
        .iter()
        .map(|(wit, non)| wit.clone().or_else(|| non.clone()))
        .collect();

    let mut cache = SighashCache::new(tx);
    let mut budget = Budget { left: MAX_SIGNATURE_CHECKS, noted: false };
    for (index, map) in inputs.iter().enumerate() {
        let scope = format!("input {index}");
        let (witness_claim, non_witness_claim) = &claims[index];
        let claim = witness_claim.clone().or_else(|| non_witness_claim.clone());
        let Some(claim) = claim else { continue }; // no claim: the fee line already says "unknown"
        if claim.script_pubkey.is_op_return() {
            problems.push(Problem::error(
                scope.clone(),
                "unspendable_prevout",
                "spends an OP_RETURN output, which is provably unspendable",
            ));
            continue;
        }
        let spend = classify(index, map, &claim, &mut problems);
        if spend.is_witness() && witness_claim.is_none() {
            problems.push(Problem::warning(
                scope.clone(),
                "missing_witness_utxo",
                "segwit input carries no witness UTXO — a signer needs it to verify the spent amount (BIP-174)",
            ));
        }
        if !spend.is_witness() && !matches!(spend, Spend::Unknown) {
            if non_witness_claim.is_none() {
                problems.push(Problem::warning(
                    scope.clone(),
                    "missing_nonwitness_utxo",
                    "non-witness input carries only a witness UTXO claim — BIP-174 expects the full previous transaction here (fee-attack exposure)",
                ));
            }
            if witness_claim.is_some() {
                problems.push(Problem::error(
                    scope.clone(),
                    "witness_utxo_on_legacy",
                    "witness UTXO declared for a non-witness input — BIP-174 forbids creating a non-witness signature against it",
                ));
            }
        }
        // The declared sighash policy: non-standard values are legal for a
        // signer to refuse, so they are named, not gated.
        if let Some(value) = input_field(map, 0x03) {
            if value.len() == 4 {
                let n = u32::from_le_bytes(value.try_into().unwrap());
                let standard = if matches!(spend, Spend::P2tr(_)) {
                    u8::try_from(n).is_ok_and(|byte| TapSighashType::from_consensus_u8(byte).is_ok())
                } else {
                    EcdsaSighashType::from_standard(n).is_ok()
                };
                if !standard {
                    problems.push(Problem::warning(
                        scope.clone(),
                        "sighash_nonstandard",
                        format!("PSBT_IN_SIGHASH_TYPE declares non-standard sighash type 0x{n:02x}"),
                    ));
                }
            }
        }
        let sighash_field = input_field(map, 0x03)
            .filter(|value| value.len() == 4)
            .map(|value| u32::from_le_bytes(value.try_into().unwrap()));
        check_partial_sigs(&mut cache, index, map, &spend, &claim, sighash_field, &mut budget, &mut problems);
        check_tap_sigs(&mut cache, index, map, &spend, &all_claims, &mut budget, &mut problems);
        let final_witness = input_field(map, 0x08).and_then(|value| Witness::consensus_decode(&mut &value[..]).ok());
        if let Some(value) = input_field(map, 0x07) {
            check_final_scriptsig(&mut cache, index, value, &spend, &claim, final_witness.is_some(), &mut budget, &mut problems);
        }
        if let Some(witness) = &final_witness {
            check_final_witness(&mut cache, index, witness, &spend, &claim, &all_claims, &mut budget, &mut problems);
        }
    }
    problems
}

/// The build gate: the error-severity problems of an about-to-be-built
/// document, as one rejection message. The transaction-sanity wording is the
/// historical gate message (tests and the UI match it); other violations
/// name themselves. Not called at all under insane editing.
pub(crate) fn gate_error(tx: &Transaction, inputs: &[Vec<RawPair>]) -> Option<String> {
    let problems = analyze(tx, inputs);
    let errors: Vec<&Problem> = problems.iter().filter(|p| p.severity == ERROR).collect();
    if errors.is_empty() {
        return None;
    }
    if errors[0].code == "tx_consensus" {
        let mut message = errors[0].message.clone();
        if errors.len() > 1 {
            message.push_str(&format!(" (and {} more problem{})", errors.len() - 1, if errors.len() > 2 { "s" } else { "" }));
        }
        return Some(message);
    }
    let listed = errors
        .iter()
        .take(3)
        .map(|p| format!("{}: {}", p.scope, p.message))
        .collect::<Vec<_>>()
        .join("; ");
    let more = if errors.len() > 3 { format!(" (and {} more)", errors.len() - 3) } else { String::new() };
    Some(format!("the edit fails Bitcoin consensus/PSBT checks — {listed}{more}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, Txid};

    fn hex(text: &str) -> Vec<u8> {
        crate::hex_decode(text).unwrap()
    }

    fn pair(key: &str, value: &str) -> RawPair {
        RawPair { key: hex(key), value: hex(value) }
    }

    // A one-input transaction spending a made-up prevout, paying 1000 sats
    // to OP_TRUE. `claim` is the TxOut the prevout is claimed to hold.
    fn fixture() -> (Transaction, TxOut) {
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp = Secp256k1::new();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2pkh(&pubkey.pubkey_hash()),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x11; 32])), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
        };
        (tx, claim)
    }

    // The witness-UTXO pair value for a TxOut: 8-byte LE amount + script.
    fn witness_utxo_value(out: &TxOut) -> String {
        let mut bytes = out.value.to_sat().to_le_bytes().to_vec();
        bytes.push(out.script_pubkey.as_bytes().len() as u8);
        bytes.extend_from_slice(out.script_pubkey.as_bytes());
        hex_encode(&bytes)
    }

    // A previous transaction paying `claim`, for non-witness UTXO pairs;
    // returns it and its txid so the spending tx can point at it.
    fn prev_tx_for(claim: &TxOut) -> (Transaction, Txid) {
        let prev = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array([0x99; 32])), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![claim.clone()],
        };
        let txid = prev.compute_txid();
        (prev, txid)
    }

    #[test]
    fn clean_p2pkh_claim_yields_no_problems() {
        let (tx, claim) = fixture();
        let (prev, txid) = prev_tx_for(&claim);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let map = vec![pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map]);
        assert_eq!(problems.len(), 0, "{problems:?}");
    }

    #[test]
    fn witness_utxo_on_a_legacy_spend_is_an_error() {
        let (tx, claim) = fixture();
        // A witness UTXO whose script is P2PKH is BIP-174's "witness UTXO
        // provided for a non-witness input" case: signer checks fail.
        let problems = analyze(&tx, &[vec![pair("01", &witness_utxo_value(&claim))]]);
        assert!(problems.iter().any(|p| p.code == "missing_nonwitness_utxo" && p.severity == WARNING));
        assert!(problems.iter().any(|p| p.code == "witness_utxo_on_legacy" && p.severity == ERROR));
        assert!(gate_error(&tx, &[vec![pair("01", &witness_utxo_value(&claim))]]).is_some());
    }

    #[test]
    fn conflicting_utxo_claims_are_an_error() {
        let (tx, claim) = fixture();
        let mut other = claim.clone();
        other.value = Amount::from_sat(60_000);
        // The non-witness claim embeds a previous transaction paying the
        // *other* amount; the spending tx points at it.
        let (prev, txid) = prev_tx_for(&other);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.iter().any(|p| p.code == "utxo_claim_conflict" && p.severity == ERROR));
    }

    #[test]
    fn nonwitness_utxo_txid_mismatch_is_an_error() {
        let (tx, claim) = fixture();
        let (prev, _txid) = prev_tx_for(&claim);
        // tx still points at [0x11; 32]:0, prev hashes to something else.
        let map = || vec![pair("00", &hex_encode(&encode::serialize(&prev)))];
        let problems = analyze(&tx, &[map()]);
        assert!(problems.iter().any(|p| p.code == "nonwitness_txid_mismatch" && p.severity == ERROR));
        assert!(gate_error(&tx, &[map()]).is_some());
    }

    #[test]
    fn a_valid_legacy_partial_signature_passes_and_a_flipped_one_is_named() {
        let (tx, claim) = fixture();
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let cache = SighashCache::new(&tx);
        let sighash = cache
            .legacy_signature_hash(0, &claim.script_pubkey, EcdsaSighashType::All.to_u32())
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut value = sig.serialize_der().to_vec();
        value.push(0x01);
        let key_hex = hex_encode(&pubkey.to_bytes());
        let good = vec![pair(&format!("02{key_hex}"), &hex_encode(&value))];
        let problems = analyze(&tx, &[good]);
        assert!(!problems.iter().any(|p| p.code == "partial_sig_invalid"), "{problems:?}");
        // Flip one byte of r: DER stays well-formed, verification fails.
        let mut bad = value.clone();
        bad[5] ^= 1;
        let badmap = vec![pair("01", &witness_utxo_value(&claim)), pair(&format!("02{key_hex}"), &hex_encode(&bad))];
        let problems = analyze(&tx, &[badmap]);
        assert!(problems.iter().any(|p| p.code == "partial_sig_invalid" && p.severity == WARNING));
    }

    #[test]
    fn strip_codeseparators_removes_opcodes_but_keeps_pushed_data() {
        // Bare opcodes go, everything else stays.
        assert_eq!(strip_codeseparators(&[0x51, 0xab, 0x52]), vec![0x51, 0x52]);
        // Separators inside a push are data, not opcodes: the push is copied
        // verbatim, and only the trailing real opcode is removed.
        assert_eq!(strip_codeseparators(&[0x02, 0xab, 0xab, 0xab]), vec![0x02, 0xab, 0xab]);
        // PUSHDATA1 payloads are copied with their header.
        assert_eq!(
            strip_codeseparators(&[0x4c, 0x03, 0xab, 0x51, 0xab, 0x51]),
            vec![0x4c, 0x03, 0xab, 0x51, 0xab, 0x51]
        );
        // A truncated push ends the walk, as Core's GetOp failure does.
        assert_eq!(strip_codeseparators(&[0x51, 0x05, 0x52]), vec![0x51]);
        // No separators: a real P2PKH scriptPubKey comes back unchanged.
        let mut plain = vec![0x76, 0xa9, 0x14];
        plain.extend_from_slice(&[0x11; 20]);
        plain.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(strip_codeseparators(&plain), plain);
    }

    #[test]
    fn a_valid_p2wpkh_final_witness_passes_and_a_wrong_key_is_an_error() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash().unwrap()),
        };
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(0, &claim.script_pubkey, claim.value, EcdsaSighashType::All)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        let sig = secp.sign_ecdsa(&message, &key);
        let mut sig_bytes = sig.serialize_der().to_vec();
        sig_bytes.push(0x01);
        let witness = Witness::from_slice(&[sig_bytes, pubkey.to_bytes()]);
        let map = vec![
            pair("01", &witness_utxo_value(&claim)),
            pair("08", &hex_encode(&encode::serialize(&witness))),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");

        // Same witness against a different key's program: must be named.
        let other_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::PublicKey::new(other_key.public_key(&secp)).wpubkey_hash().unwrap()),
        };
        let badmap = || {
            vec![
                pair("01", &witness_utxo_value(&other_claim)),
                pair("08", &hex_encode(&encode::serialize(&witness))),
            ]
        };
        let problems = analyze(&tx, &[badmap()]);
        assert!(problems.iter().any(|p| p.code == "final_witness_bad" && p.severity == ERROR));
        assert!(gate_error(&tx, &[badmap()]).is_some());
    }

    #[test]
    fn p2sh_multisig_final_scriptsig_with_op_0_dummy_is_accepted() {
        // A finalized 1-of-1 P2SH multisig: scriptSig = OP_0 <sig> <redeem>.
        // OP_0 is the CHECKMULTISIG dummy push; mistaking it for a non-push
        // would falsely gate a valid finalized input.
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pubkey = bitcoin::PublicKey::new(key.public_key(&secp));
        let redeem = ScriptBuf::from_bytes(
            [[0x51].as_slice(), &[0x21], &pubkey.to_bytes(), &[0x51, 0xae]].concat(),
        );
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2sh(&redeem.script_hash()),
        };
        // A legacy P2SH spend claims through the full previous transaction,
        // not a witness UTXO.
        let (prev, txid) = prev_tx_for(&claim);
        let mut tx = tx;
        tx.input[0].previous_output.txid = txid;
        let script_sig = ScriptBuf::from_bytes(
            [[0x00].as_slice(), &[0x02, 0xaa, 0xbb], &redeem.as_bytes().len().to_le_bytes()[..1], redeem.as_bytes()].concat(),
        );
        let map = vec![
            pair("00", &hex_encode(&encode::serialize(&prev))),
            pair("04", &hex_encode(redeem.as_bytes())),
            pair("07", &hex_encode(script_sig.as_bytes())),
        ];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_valid_taproot_key_sig_passes_and_a_flipped_one_is_named() {
        let secp = Secp256k1::new();
        let key = secp256k1::Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (xonly, _parity) = key.x_only_public_key();
        let (tx, _) = fixture();
        let claim = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr(&secp, xonly, None),
        };
        let prevouts = vec![claim.clone()];
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let message = Message::from_digest_slice(&sighash.to_byte_array()).unwrap();
        // A key-path spend signs with the tweaked key: the output key in the
        // scriptPubKey commits to the BIP-341 tweak of the internal key.
        use bitcoin::key::TapTweak as _;
        let tweaked = key.tap_tweak(&secp, None).to_keypair();
        let sig = secp.sign_schnorr_no_aux_rand(&message, &tweaked);
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("13", &hex_encode(&sig.serialize()))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.is_empty(), "{problems:?}");

        let mut bad = sig.serialize();
        bad[10] ^= 1;
        let map = vec![pair("01", &witness_utxo_value(&claim)), pair("13", &hex_encode(&bad))];
        let problems = analyze(&tx, &[map]);
        assert!(problems.iter().any(|p| p.code == "tap_sig_invalid" && p.severity == WARNING));
    }
}

