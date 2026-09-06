//! Offline BIP-322 verification for EntropyLab.
//! Signature/script verification is delegated to rust-bitcoin/bip322 0.0.11.

use bip322::{create_to_spend, tagged_hash, verify_full_encoded, verify_pof_encoded, verify_simple_encoded, BIP322_TAG, PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE};
use bitcoin::{psbt::raw::Key, psbt::Psbt, Address, Sequence};
use serde_json::{json, Value};
use std::str::FromStr;

const MAX_MESSAGE_BYTES: usize = 330;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_SIGNATURE_BYTES: usize = 2_000_000;

fn hex_encode(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes { out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 0x0f) as usize] as char); }
    out
}

fn result_json(state: &str, prefix: &str, message_hash: Value, challenge_type: Value, time_locks: Option<Value>, pof_claims: Option<Value>, error: Option<&str>) -> String {
    let mut result = serde_json::Map::new();
    result.insert("state".into(), json!(state));
    result.insert("prefix".into(), json!(prefix));
    result.insert("message_hash".into(), message_hash);
    result.insert("challenge_type".into(), challenge_type);
    if let Some(value) = time_locks { result.insert("time_locks".into(), value); }
    if let Some(value) = pof_claims { result.insert("pof_claims".into(), value); }
    if let Some(value) = error { result.insert("error".into(), json!(value)); }
    Value::Object(result).to_string()
}

fn invalid(prefix: &str, error: &str) -> String { result_json("invalid", prefix, Value::Null, Value::Null, None, None, Some(error)) }

fn classify_challenge(address: &Address) -> &'static str {
    let script = address.script_pubkey();
    if script.is_p2pkh() { "p2pkh" }
    else if script.is_p2wpkh() { "p2wpkh" }
    else if script.is_p2tr() { "p2tr" }
    else if script.is_p2wsh() { "p2wsh" }
    else if script.is_p2sh() { "p2sh" }
    else { "unsupported" }
}

fn valid_message(message: &str) -> Result<(), &'static str> {
    let bytes = message.as_bytes();
    if bytes.len() < 2 || bytes.len() > MAX_MESSAGE_BYTES { return Err("message must be 2-330 ASCII bytes"); }
    if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) { return Err("message must contain only printable ASCII characters"); }
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') { return Err("message must not begin or end with a space"); }
    if bytes.windows(3).any(|w| w == b"   ") { return Err("message must not contain three consecutive spaces"); }
    Ok(())
}

fn parse_signature(signature: &str) -> (&str, &str) {
    if let Some(rest) = signature.strip_prefix("smp:") { ("smp", rest) }
    else if let Some(rest) = signature.strip_prefix("ful:") { ("ful", rest) }
    else if let Some(rest) = signature.strip_prefix("pof:") { ("pof", rest) }
    else { ("smp", signature) }
}

fn time_lock_state(tx: &bitcoin::Transaction) -> (bool, Value) {
    let locktime = tx.lock_time.to_consensus_u32();
    let relative = tx.input.iter().map(|input| input.sequence.to_consensus_u32()).filter(|seq| *seq != Sequence::MAX.to_consensus_u32()).collect::<Vec<_>>();
    let active = locktime != 0 || !relative.is_empty();
    (active, json!({"nLockTime": locktime, "nSequence": relative, "active": active}))
}

fn verify(message: &str, address_text: &str, signature: &str) -> String {
    let (prefix, encoded) = parse_signature(signature);
    if let Err(error) = valid_message(message) { return invalid(prefix, error); }
    if address_text.len() > MAX_ADDRESS_BYTES { return invalid(prefix, "address or descriptor is too long"); }
    if signature.len() > MAX_SIGNATURE_BYTES { return invalid(prefix, "signature is too large"); }
    let address = match Address::from_str(address_text) { Ok(address) => address.assume_checked(), Err(_) => return invalid(prefix, "unsupported address or descriptor") };
    let challenge_type = classify_challenge(&address).to_string();
    let message_hash = hex_encode(&tagged_hash(BIP322_TAG, message));

    let verified = match prefix {
        "smp" => verify_simple_encoded(address_text, message, encoded).is_ok(),
        "ful" => verify_full_encoded(address_text, message, encoded).is_ok(),
        "pof" => {
            let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded) { Ok(bytes) => bytes, Err(_) => return invalid(prefix, "invalid proof-of-funds PSBT encoding") };
            let psbt = match Psbt::deserialize(&bytes) { Ok(psbt) => psbt, Err(_) => return invalid(prefix, "invalid proof-of-funds PSBT") };
            let message_key = Key { type_value: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE, key: vec![] };
            let Some(generic_message) = psbt.unknown.get(&message_key) else { return invalid(prefix, "proof-of-funds PSBT has no generic signed message (0x09)") };
            if generic_message.as_slice() != message.as_bytes() { return invalid(prefix, "PSBT generic signed message (0x09) does not match the supplied message"); }
            let to_spend = match create_to_spend(&address, message) { Ok(tx) => tx, Err(_) => return invalid(prefix, "could not construct BIP-322 challenge") };
            let expected = tagged_hash(BIP322_TAG, message);
            let script = to_spend.input[0].script_sig.as_bytes();
            if script.len() != 34 || script[0] != 0x00 || script[1] != 0x20 || script[2..] != expected { return invalid(prefix, "BIP-322 challenge hash is not the expected PUSH32 in to_spend scriptSig"); }
            let mut prevouts = Vec::with_capacity(psbt.inputs.len().saturating_sub(1));
            for (index, input) in psbt.inputs.iter().enumerate().skip(1) {
                if let Some(txout) = &input.witness_utxo { prevouts.push(txout.clone()); continue; }
                let Some(tx) = &input.non_witness_utxo else { return invalid(prefix, "proof-of-funds input lacks a witness_utxo or non_witness_utxo") };
                let outpoint = &psbt.unsigned_tx.input[index].previous_output;
                let Some(txout) = tx.output.get(outpoint.vout as usize) else { return invalid(prefix, "non_witness_utxo does not contain its referenced output") };
                prevouts.push(txout.clone());
            }
            verify_pof_encoded(address_text, message, encoded, &prevouts).is_ok()
        }
        _ => false,
    };

    if !verified {
        return result_json("invalid", prefix, json!(message_hash), json!(challenge_type), None,
            if prefix == "pof" { Some(json!({"verified_amounts": false, "unspent": "not_checked"})) } else { None },
            Some("BIP-322 proof verification failed"));
    }

    let locks = if prefix == "ful" {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()
            .and_then(|bytes| bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes).ok())
            .map(|tx| time_lock_state(&tx))
    } else { None };
    let state = locks.as_ref().filter(|(active, _)| *active).map_or("valid", |_| "inconclusive");
    result_json(state, prefix, json!(message_hash), json!(challenge_type), locks.map(|(_, value)| value),
        if prefix == "pof" { Some(json!({"verified_amounts": true, "unspent": "not_checked", "privacy_warning": "PSBT data may reveal UTXOs, scripts, pubkeys, and derivation hints; do not paste it into online services."})) } else { None }, None)
}

#[no_mangle]
pub unsafe extern "C" fn bip322_verify(message_ptr: *const u8, message_len: usize, address_ptr: *const u8, address_len: usize, signature_ptr: *const u8, signature_len: usize, out: *mut u8, out_cap: usize) -> i32 {
    if message_ptr.is_null() || address_ptr.is_null() || signature_ptr.is_null() { return -1; }
    let message = match std::str::from_utf8(std::slice::from_raw_parts(message_ptr, message_len)) { Ok(value) => value, Err(_) => return -1 };
    let address = match std::str::from_utf8(std::slice::from_raw_parts(address_ptr, address_len)) { Ok(value) => value, Err(_) => return -1 };
    let signature = match std::str::from_utf8(std::slice::from_raw_parts(signature_ptr, signature_len)) { Ok(value) => value, Err(_) => return -1 };
    let result = verify(message, address, signature);
    if out.is_null() { return result.len() as i32; }
    if out_cap < result.len() { return -1; }
    std::ptr::copy_nonoverlapping(result.as_ptr(), out, result.len());
    result.len() as i32
}
