//! Offline BIP-322 verification for EntropyLab.
//! Cryptographic verification is delegated to rust-bitcoin/bip322 0.0.11.

use bip322::{
    create_to_spend, tagged_hash, verify_full_encoded, verify_legacy_encoded,
    verify_pof_encoded, verify_simple_encoded, BIP322_TAG, PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
};
use bitcoin::{psbt::raw::Key, psbt::Psbt, Address, Sequence};
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

fn result_json(
    state: &str,
    prefix: &str,
    message_hash: Value,
    challenge_type: Value,
    time_locks: Option<Value>,
    pof_claims: Option<Value>,
    error: Option<&str>,
) -> String {
    let mut result = serde_json::Map::new();
    result.insert("state".into(), json!(state));
    result.insert("prefix".into(), json!(prefix));
    result.insert("message_hash".into(), message_hash);
    result.insert("challenge_type".into(), challenge_type);
    if let Some(value) = time_locks {
        result.insert("time_locks".into(), value);
    }
    if let Some(value) = pof_claims {
        result.insert("pof_claims".into(), value);
    }
    if let Some(value) = error {
        result.insert("error".into(), json!(value));
    }
    Value::Object(result).to_string()
}

fn invalid(prefix: &str, error: &str) -> String {
    result_json(
        "invalid",
        prefix,
        Value::Null,
        Value::Null,
        None,
        None,
        Some(error),
    )
}

fn classify_challenge(address: &Address) -> &'static str {
    let script = address.script_pubkey();
    if script.is_p2pkh() {
        "p2pkh"
    } else if script.is_p2wpkh() {
        "p2wpkh"
    } else if script.is_p2tr() {
        "p2tr"
    } else if script.is_p2wsh() {
        "p2wsh"
    } else if script.is_p2sh() {
        "p2sh"
    } else {
        "unsupported"
    }
}

/// BIP-322 proof-of-funds applies this restriction to the PSBT 0x09 message.
fn valid_pof_message(message: &str) -> Result<(), &'static str> {
    let bytes = message.as_bytes();
    if bytes.len() < 2 || bytes.len() > MAX_MESSAGE_BYTES {
        return Err("proof-of-funds message must be 2-330 ASCII bytes");
    }
    if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err("proof-of-funds message must contain only printable ASCII characters");
    }
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
        return Err("proof-of-funds message must not begin or end with a space");
    }
    if bytes.windows(3).any(|w| w == b"   ") {
        return Err("proof-of-funds message must not contain three consecutive spaces");
    }
    Ok(())
}

/// Final BIP-322 prefixes use `/`, not `:`. A prefixless input is the simple
/// variant for compatibility with pre-1.0 implementations. Legacy BIP-137 is
/// tried separately for a P2PKH address when the prefix is absent.
fn parse_signature(signature: &str) -> (&str, &str, bool) {
    if let Some(rest) = signature.strip_prefix("smp/") {
        ("smp", rest, true)
    } else if let Some(rest) = signature.strip_prefix("ful/") {
        ("ful", rest, true)
    } else if let Some(rest) = signature.strip_prefix("pof/") {
        ("pof", rest, true)
    } else {
        ("smp", signature, false)
    }
}

fn time_lock_state(tx: &bitcoin::Transaction) -> (bool, Value) {
    let locktime = tx.lock_time.to_consensus_u32();
    let absolute_active = tx.is_lock_time_enabled() && locktime != 0;
    let relative: Vec<u32> = tx
        .input
        .iter()
        .filter(|input| input.sequence.is_relative_lock_time())
        .map(|input| input.sequence.to_consensus_u32())
        .filter(|seq| *seq & 0x0000ffff != 0)
        .collect();
    let active = absolute_active || !relative.is_empty();
    (
        active,
        json!({
            "nLockTime": locktime,
            "nSequence": relative,
            "active": active
        }),
    )
}

fn verify(message: &str, address_text: &str, signature: &str) -> String {
    let (requested_prefix, encoded, explicit_prefix) = parse_signature(signature);
    if address_text.len() > MAX_ADDRESS_BYTES {
        return invalid(requested_prefix, "address is too long");
    }
    if signature.len() > MAX_SIGNATURE_BYTES {
        return invalid(requested_prefix, "signature is too large");
    }
    let address = match Address::from_str(address_text) {
        Ok(address) => address.assume_checked(),
        Err(_) => return invalid(requested_prefix, "unsupported address"),
    };
    let challenge_type = classify_challenge(&address).to_string();
    let message_hash = hex_encode(&tagged_hash(BIP322_TAG, message));

    // The issue's legacy form is intentionally unprefixed. It is unambiguous
    // enough for P2PKH because the 65-byte recoverable signature cannot be a
    // valid BIP-322 witness encoding. Do not make a legacy attempt for other
    // address types.
    if !explicit_prefix && address.script_pubkey().is_p2pkh() {
        if verify_legacy_encoded(address_text, message, encoded).is_ok() {
            return result_json(
                "valid",
                "legacy",
                json!(message_hash),
                json!(challenge_type),
                None,
                None,
                None,
            );
        }
    }

    if requested_prefix == "pof" {
        if let Err(error) = valid_pof_message(message) {
            return invalid("pof", error);
        }
    }

    let verified = match requested_prefix {
        "smp" => verify_simple_encoded(address_text, message, encoded).is_ok(),
        "ful" => verify_full_encoded(address_text, message, encoded).is_ok(),
        "pof" => {
            let bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                encoded,
            ) {
                Ok(bytes) => bytes,
                Err(_) => return invalid("pof", "invalid proof-of-funds PSBT encoding"),
            };
            let psbt = match Psbt::deserialize(&bytes) {
                Ok(psbt) => psbt,
                Err(_) => return invalid("pof", "invalid proof-of-funds PSBT"),
            };
            let message_key = Key {
                type_value: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
                key: vec![],
            };
            let Some(generic_message) = psbt.unknown.get(&message_key) else {
                return invalid("pof", "proof-of-funds PSBT has no generic signed message (0x09)");
            };
            if generic_message.as_slice() != message.as_bytes() {
                return invalid(
                    "pof",
                    "PSBT generic signed message (0x09) does not match the supplied message",
                );
            }
            let mut prevouts = Vec::with_capacity(psbt.inputs.len().saturating_sub(1));
            for (index, input) in psbt.inputs.iter().enumerate().skip(1) {
                if let Some(txout) = &input.witness_utxo {
                    prevouts.push(txout.clone());
                    continue;
                }
                let Some(tx) = &input.non_witness_utxo else {
                    return invalid(
                        "pof",
                        "proof-of-funds input lacks a witness_utxo or non_witness_utxo",
                    );
                };
                let outpoint = &psbt.unsigned_tx.input[index].previous_output;
                let Some(txout) = tx.output.get(outpoint.vout as usize) else {
                    return invalid("pof", "non_witness_utxo does not contain its referenced output");
                };
                prevouts.push(txout.clone());
            }
            verify_pof_encoded(address_text, message, encoded, &prevouts).is_ok()
        }
        _ => false,
    };

    if !verified {
        return result_json(
            "invalid",
            requested_prefix,
            json!(message_hash),
            json!(challenge_type),
            None,
            if requested_prefix == "pof" {
                Some(json!({
                    "verified_amounts": false,
                    "unspent": "not_checked"
                }))
            } else {
                None
            },
            Some("BIP-322 proof verification failed"),
        );
    }

    let locks = if requested_prefix == "ful" {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .ok()
            .and_then(|bytes| {
                bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes).ok()
            })
            .map(|tx| time_lock_state(&tx))
    } else {
        None
    };
    let state = locks
        .as_ref()
        .filter(|(active, _)| *active)
        .map_or("valid", |_| "inconclusive");
    result_json(
        state,
        requested_prefix,
        json!(message_hash),
        json!(challenge_type),
        locks.map(|(_, value)| value),
        if requested_prefix == "pof" {
            Some(json!({
                "verified_amounts": true,
                "unspent": "not_checked",
                "privacy_warning": "PSBT data may reveal UTXOs, scripts, pubkeys, and derivation hints; do not paste it into online services."
            }))
        } else {
            None
        },
        None,
    )
}

#[no_mangle]
pub unsafe extern "C" fn bip322_verify(
    message_ptr: *const u8,
    message_len: usize,
    address_ptr: *const u8,
    address_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if message_ptr.is_null() || address_ptr.is_null() || signature_ptr.is_null() {
        return -1;
    }
    let message = match std::str::from_utf8(std::slice::from_raw_parts(message_ptr, message_len)) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let address = match std::str::from_utf8(std::slice::from_raw_parts(address_ptr, address_len)) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let signature = match std::str::from_utf8(std::slice::from_raw_parts(signature_ptr, signature_len)) {
        Ok(value) => value,
        Err(_) => return -1,
    };
    let result = verify(message, address, signature);
    if out.is_null() {
        return result.len() as i32;
    }
    if out_cap < result.len() {
        return -1;
    }
    std::ptr::copy_nonoverlapping(result.as_ptr(), out, result.len());
    result.len() as i32
}
