//! Offline BIP-322 verification for EntropyLab.
//! Cryptographic verification is delegated to rust-bitcoin/bip322 0.0.12.

use bip322::{
    tagged_hash, verify_full_encoded, verify_legacy_encoded, verify_pof_encoded,
    verify_simple_encoded, BIP322_TAG, PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, Verification,
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

fn result_json(
    state: &str,
    prefix: &str,
    message_hash: Value,
    challenge_type: Value,
    time_locks: Option<Value>,
    pof_claims: Option<Value>,
    pof_message: Option<Value>,
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
    if let Some(value) = pof_message {
        result.insert("signed_message_0x09".into(), value);
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

/// Parse the BIP-322 variant prefix without changing the encoded signature.
///
/// Canonical signatures are `smp<base64>`, `ful<base64>`, or `pof<base64>`.
/// Prefixless input is treated as the simple variant for backwards
/// compatibility. The old `smp/...` form is deliberately rejected: `/` is
/// part of the base64 alphabet and is not a BIP-322 prefix separator.
fn parse_signature(signature: &str) -> (&str, &str, bool) {
    if signature.starts_with("smp/") || signature.starts_with("ful/") || signature.starts_with("pof/") {
        return ("unknown", signature, true);
    }
    if signature.starts_with("smp") {
        return ("smp", &signature[3..], true);
    }
    if signature.starts_with("ful") {
        return ("ful", &signature[3..], true);
    }
    if signature.starts_with("pof") {
        return ("pof", &signature[3..], true);
    }
    if signature.len() >= 4
        && signature.as_bytes()[0].is_ascii_alphabetic()
        && signature.as_bytes()[1].is_ascii_alphabetic()
        && signature.as_bytes()[2].is_ascii_alphabetic()
        && signature.as_bytes()[3] == b'/'
    {
        return ("unknown", signature, true);
    }
    ("smp", signature, false)
}

fn verification_state(verification: &Verification) -> (&'static str, Option<Value>) {
    match verification {
        Verification::Inconclusive => ("inconclusive", None),
        Verification::Valid { time, age } => {
            let lock_time = time.to_consensus_u32();
            let relative = age.to_consensus_u32();
            let active = lock_time != 0 || (age.is_relative_lock_time() && relative != 0);
            (
                if active { "inconclusive" } else { "valid" },
                Some(json!({
                    "nLockTime": lock_time,
                    "nSequence": relative,
                    "active": active,
                    "T": lock_time,
                    "S": relative
                })),
            )
        }
    }
}

fn pof_details(psbt: &Psbt) -> (Option<String>, Vec<Value>) {
    let message_key = Key {
        type_value: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE,
        key: vec![],
    };
    let message = psbt
        .unknown
        .get(&message_key)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_owned);

    let mut claims = Vec::with_capacity(psbt.inputs.len().saturating_sub(1));
    for (index, input) in psbt.inputs.iter().enumerate().skip(1) {
        let outpoint = &psbt.unsigned_tx.input[index].previous_output;
        let amount_sat = input
            .witness_utxo
            .as_ref()
            .map(|txout| txout.value.to_sat())
            .or_else(|| {
                input
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|tx| tx.output.get(outpoint.vout as usize))
                    .map(|txout| txout.value.to_sat())
            });
        claims.push(json!({
            "outpoint": outpoint.to_string(),
            "amount_sat": amount_sat,
            "label": "unverified claim from finalized PSBT — does NOT prove unspent, completeness, exclusive ownership"
        }));
    }
    (message, claims)
}

fn verify(message: &str, address_text: &str, signature: &str) -> String {
    let (requested_prefix, encoded, explicit_prefix) = parse_signature(signature);
    if requested_prefix == "unknown" {
        return invalid("unknown", "unknown BIP-322 signature prefix");
    }
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

    if !explicit_prefix && address.script_pubkey().is_p2pkh() {
        if verify_legacy_encoded(address_text, message, encoded).is_ok() {
            return result_json(
                "valid",
                "legacy",
                Value::Null,
                json!(challenge_type),
                None,
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

    let verification = match requested_prefix {
        "smp" => verify_simple_encoded(address_text, message, signature),
        "ful" => verify_full_encoded(address_text, message, signature),
        "pof" => verify_pof_encoded(address_text, message, signature),
        _ => return invalid(requested_prefix, "unsupported BIP-322 signature variant"),
    };

    let pof_data = if requested_prefix == "pof" {
        let bytes = match base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded,
        ) {
            Ok(bytes) => bytes,
            Err(_) => return invalid("pof", "invalid proof-of-funds PSBT encoding"),
        };
        match Psbt::deserialize(&bytes) {
            Ok(psbt) => {
                let (message_0x09, claims) = pof_details(&psbt);
                if message_0x09.as_deref() != Some(message) {
                    return invalid(
                        "pof",
                        "PSBT generic signed message (0x09) does not match the supplied message",
                    );
                }
                Some((message_0x09, claims))
            }
            Err(_) => return invalid("pof", "invalid proof-of-funds PSBT"),
        }
    } else {
        None
    };

    let verification = match verification {
        Ok(value) => value,
        Err(_) => {
            return result_json(
                "invalid",
                requested_prefix,
                json!(message_hash),
                json!(challenge_type),
                None,
                pof_data.as_ref().map(|(_, claims)| json!({
                    "verified_amounts": false,
                    "claim_source": "finalized_psbt",
                    "unspent": "not_checked",
                    "claims": claims,
                    "privacy_warning": "PSBT data may reveal UTXOs, scripts, pubkeys, and derivation hints; do not paste it into online services."
                })),
                pof_data.as_ref().and_then(|(message, _)| message.as_ref().map(|value| json!(value))),
                Some("BIP-322 proof verification failed"),
            );
        }
    };

    let (state, time_locks) = verification_state(&verification);
    result_json(
        state,
        requested_prefix,
        json!(message_hash),
        json!(challenge_type),
        time_locks,
        pof_data.as_ref().map(|(_, claims)| json!({
            "verified_amounts": false,
            "claim_source": "finalized_psbt",
            "unspent": "not_checked",
            "claims": claims,
            "privacy_warning": "PSBT data may reveal UTXOs, scripts, pubkeys, and derivation hints; do not paste it into online services."
        })),
        pof_data.as_ref().and_then(|(message, _)| message.as_ref().map(|value| json!(value))),
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
