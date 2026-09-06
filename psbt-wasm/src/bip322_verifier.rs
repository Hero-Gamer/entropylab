//! Offline BIP-322 verification for EntropyLab.
//! Cryptographic verification is delegated to rust-bitcoin/bip322 0.0.12.

use bip322::{
    tagged_hash, verify_full_encoded, verify_legacy_encoded, verify_pof_encoded,
    verify_simple_encoded, BIP322_TAG, PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
};
use bitcoin::{psbt::raw::Key, psbt::Psbt, Address};
use serde_json::{json, Value};
use std::str::FromStr;

const MAX_MESSAGE_BYTES: usize = 330;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 2_000_000;

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn invalid(prefix: &str, error: &str) -> Value {
    json!({"state":"invalid","prefix":prefix,"error":error})
}

fn result_json(
    state: &str,
    prefix: &str,
    message_hash: Value,
    challenge_type: Value,
    time_locks: Option<Value>,
    proof_of_funds: Option<Value>,
    warning: Option<&str>,
) -> Value {
    let mut result = json!({
        "state": state,
        "prefix": prefix,
        "message_hash": message_hash,
        "challenge_type": challenge_type,
    });
    if let Some(value) = time_locks {
        result["time_locks"] = value;
    }
    if let Some(value) = proof_of_funds {
        result["proof_of_funds"] = value;
    }
    if let Some(value) = warning {
        result["warning"] = json!(value);
    }
    result
}

fn classify_challenge(address: &Address) -> &'static str {
    let script = address.script_pubkey();
    if script.is_p2pkh() { "p2pkh" }
    else if script.is_p2wpkh() { "p2wpkh" }
    else if script.is_p2tr() { "p2tr" }
    else if script.is_p2wsh() { "p2wsh" }
    else if script.is_p2sh() { "p2sh" }
    else { "unsupported" }
}

fn valid_pof_message(message: &str) -> Result<(), &'static str> {
    let bytes = message.as_bytes();
    if !(2..=MAX_MESSAGE_BYTES).contains(&bytes.len()) {
        return Err("proof-of-funds message must be 2-330 bytes");
    }
    if !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err("proof-of-funds message must contain printable ASCII only");
    }
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
        return Err("proof-of-funds message must not start or end with a space");
    }
    if bytes.windows(3).any(|window| window == b"   ") {
        return Err("proof-of-funds message must not contain three consecutive spaces");
    }
    Ok(())
}

fn time_lock_state(tx: &bitcoin::Transaction) -> Value {
    let absolute_enabled = tx.is_lock_time_enabled() && tx.lock_time != bitcoin::absolute::LockTime::ZERO;
    let relative = tx.input.iter().any(|input| input.sequence.is_relative_lock_time());
    let active = absolute_enabled || relative;
    json!({
        "nLockTime": tx.lock_time.to_consensus_u32(),
        "active": active,
        "relative": relative,
    })
}

fn parse_signature(signature: &str) -> (&str, &str, bool) {
    if let Some((prefix, encoded)) = signature.split_once('/') {
        (prefix, encoded, true)
    } else {
        ("smp", signature, false)
    }
}

pub fn verify(message: &str, address_text: &str, signature: &str) -> Value {
    if message.as_bytes().len() > MAX_MESSAGE_BYTES {
        return invalid("", "message exceeds 330 bytes");
    }
    if address_text.len() > MAX_ADDRESS_BYTES {
        return invalid("", "address exceeds 256 bytes");
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return invalid("", "signature exceeds maximum size");
    }
    let (requested_prefix, encoded, explicit_prefix) = parse_signature(signature);
    if !matches!(requested_prefix, "smp" | "ful" | "pof") {
        return invalid(requested_prefix, "unknown BIP-322 signature prefix");
    }
    let address = match Address::from_str(address_text) {
        Ok(address) => address.assume_checked(),
        Err(_) => return invalid(requested_prefix, "unsupported or invalid address"),
    };
    let challenge_type = classify_challenge(&address).to_string();
    if challenge_type == "unsupported" {
        return invalid(requested_prefix, "unsupported challenge type");
    }
    let message_hash = hex_encode(&tagged_hash(BIP322_TAG, message));

    if !explicit_prefix && address.script_pubkey().is_p2pkh() {
        if verify_legacy_encoded(address_text, message, encoded).is_ok() {
            return result_json("valid", "legacy", Value::Null, json!(challenge_type), None, None,
                Some("Legacy P2PKH-only, deprecated — BIP-137 / Electrum style, not generic"));
        }
    }

    if requested_prefix == "pof" {
        if let Err(error) = valid_pof_message(message) { return invalid("pof", error); }
    }

    let verified = match requested_prefix {
        "smp" => verify_simple_encoded(address_text, message, encoded).is_ok(),
        "ful" => verify_full_encoded(address_text, message, encoded).is_ok(),
        "pof" => {
            let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) {
                Ok(bytes) => bytes,
                Err(_) => return invalid("pof", "invalid proof-of-funds PSBT encoding"),
            };
            let psbt = match Psbt::deserialize(&bytes) {
                Ok(psbt) => psbt,
                Err(_) => return invalid("pof", "invalid proof-of-funds PSBT"),
            };
            let message_key = Key { type_value: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, key: vec![] };
            let Some(generic_message) = psbt.unknown.get(&message_key) else {
                return invalid("pof", "proof-of-funds PSBT has no generic signed message (0x09)");
            };
            if generic_message.as_slice() != message.as_bytes() {
                return invalid("pof", "PSBT generic signed message (0x09) does not match the supplied message");
            }
            verify_pof_encoded(address_text, message, encoded).is_ok()
        }
        _ => false,
    };

    if !verified {
        return result_json("invalid", requested_prefix, json!(message_hash), json!(challenge_type), None,
            if requested_prefix == "pof" { Some(json!({"verified_amounts":false,"claim_source":"finalized_psbt","unspent":"not_checked"})) } else { None },
            Some("BIP-322 proof verification failed"));
    }

    let locks = if requested_prefix == "ful" {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .ok().and_then(|bytes| Psbt::deserialize(&bytes).ok())
            .map(|psbt| time_lock_state(&psbt.unsigned_tx))
    } else { None };
    let state = if locks.as_ref().and_then(|v| v.get("active")).and_then(Value::as_bool).unwrap_or(false) {
        "inconclusive"
    } else { "valid" };
    result_json(state, requested_prefix, json!(message_hash), json!(challenge_type), locks,
        if requested_prefix == "pof" { Some(json!({"verified_amounts":false,"claim_source":"finalized_psbt","unspent":"not_checked"})) } else { None },
        if requested_prefix == "pof" { Some("Cryptographically valid offline — unspent NOT checked; the PSBT may reveal UTXOs, scripts, public keys, and derivation metadata") } else { None })
}

pub fn verify_json(message: &str, address: &str, signature: &str) -> String {
    serde_json::to_string(&verify(message, address, signature)).unwrap_or_else(|_| "{\"state\":\"invalid\",\"error\":\"serialization failure\"}".to_string())
}
