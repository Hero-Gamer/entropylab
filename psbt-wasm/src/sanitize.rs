//! PSBT inspect sanitizer: two families only.
//!
//! 1. `duplicate_keys` — BIP-174 forbids duplicate keys *within one map*.
//!    Scan each map's `Vec<RawPair>` (not a hashed map) so a second identical
//!    `type||keydata` is a finding instead of a silent overwrite.
//! 2. `xpub_derives_child` — when a bip32/tap derivation claims an origin,
//!    check it against *applicable* global xpubs (master fingerprint match +
//!    path prefix + unhardened suffix). A 32-byte key is compared as x-only.
//!
//! These are format / origin-consistency facts, not a safety verdict.
//! A derivation that cannot be checked (no applicable xpub, hardened gap)
//! is `incomplete`, never a pass. rust-bitcoin's own parse verdict stays in
//! `rustBitcoinError` and is not replaced.

use crate::{hex_encode, pair_type_name, read_varint, RawPair};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use serde_json::{json, Value};
use std::collections::HashSet;

const MAX_FINDINGS: usize = 32;

struct Origin {
    fingerprint: [u8; 4],
    path: Vec<ChildNumber>,
}

struct GlobalXpub {
    fingerprint: [u8; 4],
    path: Vec<ChildNumber>,
    xpub: Xpub,
}

fn family(state: &str, findings: Vec<Value>, truncated: bool) -> Value {
    json!({ "state": state, "findings": findings, "truncated": truncated })
}

fn push(findings: &mut Vec<Value>, truncated: &mut bool, finding: Value) {
    if findings.len() >= MAX_FINDINGS {
        *truncated = true;
        return;
    }
    findings.push(finding);
}

fn parse_origin(value: &[u8]) -> Result<Origin, String> {
    if value.len() < 4 {
        return Err("derivation value is shorter than its 4-byte fingerprint".into());
    }
    if (value.len() - 4) % 4 != 0 {
        return Err("derivation path is not a multiple of 4 bytes".into());
    }
    let fingerprint = value[..4].try_into().unwrap();
    let path = value[4..]
        .chunks_exact(4)
        .map(|c| ChildNumber::from(u32::from_le_bytes(c.try_into().unwrap())))
        .collect();
    Ok(Origin { fingerprint, path })
}

fn tap_origin(value: &[u8]) -> Result<Origin, String> {
    let mut off = 0usize;
    let count = read_varint(value, &mut off)?;
    let hashes_end = usize::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(32))
        .and_then(|l| off.checked_add(l))
        .filter(|end| end.checked_add(4).is_some_and(|e| e <= value.len()))
        .ok_or_else(|| "tap bip32 derivation is truncated".to_string())?;
    parse_origin(&value[hashes_end..])
}

fn fp_hex(fp: &[u8; 4]) -> String {
    hex_encode(fp) // 8 hex chars; the full fingerprint, never the value bytes
}

fn finding_duplicate(kind: &str, index: Option<usize>, pair: &RawPair) -> Value {
    let type_byte = pair.key[0];
    json!({
        "code": "duplicate_key",
        "scope": kind,
        "index": index,
        "key": hex_encode(&pair.key),
        "name": pair_type_name(kind, type_byte),
    })
}

fn finding_origin(
    kind: &str,
    index: Option<usize>,
    pair: &RawPair,
    fingerprint: Option<[u8; 4]>,
    reason: &str,
) -> Value {
    let type_byte = pair.key[0];
    json!({
        "code": "xpub_derives_child",
        "scope": kind,
        "index": index,
        "key": hex_encode(&pair.key),
        "name": pair_type_name(kind, type_byte),
        "fingerprint": fingerprint.map(|fp| fp_hex(&fp)),
        "reason": reason,
    })
}

fn duplicate_keys(kind: &str, index: Option<usize>, pairs: &[RawPair]) -> (Vec<Value>, bool) {
    let mut seen = HashSet::<&[u8]>::new();
    let mut findings = Vec::new();
    let mut truncated = false;
    for pair in pairs {
        if pair.key.is_empty() {
            continue;
        }
        if !seen.insert(pair.key.as_slice()) {
            push(
                &mut findings,
                &mut truncated,
                finding_duplicate(kind, index, pair),
            );
        }
    }
    (findings, truncated)
}

fn collect_xpubs(globals: &[RawPair]) -> Vec<GlobalXpub> {
    let mut out = Vec::new();
    for pair in globals {
        if pair.key.first() != Some(&0x01) || pair.key.len() < 2 {
            continue;
        }
        let Ok(xpub) = Xpub::decode(&pair.key[1..]) else {
            continue;
        };
        let Ok(origin) = parse_origin(&pair.value) else {
            continue;
        };
        out.push(GlobalXpub {
            fingerprint: origin.fingerprint,
            path: origin.path,
            xpub,
        });
    }
    out
}

fn pubkeys_match(observed: &[u8], derived: &PublicKey) -> bool {
    let compressed = derived.serialize();
    if observed == compressed.as_slice() {
        return true;
    }
    // BIP-371 x-only: 32-byte keydata is the x coordinate of the compressed key.
    if observed.len() == 32 && observed == &compressed[1..] {
        return true;
    }
    if observed.len() == 65 {
        let uncompressed = derived.serialize_uncompressed();
        return observed == uncompressed.as_slice();
    }
    false
}

fn path_prefix(prefix: &[ChildNumber], full: &[ChildNumber]) -> Option<Vec<ChildNumber>> {
    if full.len() < prefix.len() {
        return None;
    }
    if full[..prefix.len()] != prefix[..] {
        return None;
    }
    Some(full[prefix.len()..].to_vec())
}

/// Applicable = same master fingerprint, xpub path is a prefix of the child
/// path, and the remaining suffix is unhardened (so `Xpub::derive_pub` can
/// actually run). Hardened suffixes are not mismatches; they are not checked.
fn applicable<'a>(
    xpubs: &'a [GlobalXpub],
    origin: &Origin,
) -> (Vec<(&'a Xpub, Vec<ChildNumber>)>, bool) {
    let mut candidates = Vec::new();
    let mut hardened_gap = false;
    for xpub in xpubs {
        if xpub.fingerprint != origin.fingerprint {
            continue;
        }
        let Some(suffix) = path_prefix(&xpub.path, &origin.path) else {
            continue;
        };
        if suffix.iter().any(|c| c.is_hardened()) {
            hardened_gap = true;
            continue;
        }
        candidates.push((&xpub.xpub, suffix));
    }
    (candidates, hardened_gap)
}

fn check_one_derivation(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    xpubs: &[GlobalXpub],
    kind: &str,
    index: Option<usize>,
    pair: &RawPair,
    origin: Result<Origin, String>,
    findings: &mut Vec<Value>,
    truncated: &mut bool,
    saw_incomplete: &mut bool,
    saw_problem: &mut bool,
) {
    let observed = &pair.key[1..];
    let origin = match origin {
        Ok(o) => o,
        Err(_) => {
            *saw_incomplete = true;
            push(
                findings,
                truncated,
                finding_origin(kind, index, pair, None, "malformed"),
            );
            return;
        }
    };
    let (candidates, hardened_gap) = applicable(xpubs, &origin);
    if candidates.is_empty() {
        *saw_incomplete = true;
        let reason = if hardened_gap {
            "hardened_gap"
        } else {
            "no_applicable_xpub"
        };
        push(
            findings,
            truncated,
            finding_origin(kind, index, pair, Some(origin.fingerprint), reason),
        );
        return;
    }
    for (xpub, suffix) in &candidates {
        let derived = if suffix.is_empty() {
            xpub.public_key
        } else {
            match xpub.derive_pub(secp, suffix) {
                Ok(child) => child.public_key,
                Err(_) => continue,
            }
        };
        if pubkeys_match(observed, &derived) {
            return;
        }
    }
    *saw_problem = true;
    push(
        findings,
        truncated,
        finding_origin(kind, index, pair, Some(origin.fingerprint), "mismatch"),
    );
}

fn scan_derivations(
    secp: &Secp256k1<bitcoin::secp256k1::VerifyOnly>,
    xpubs: &[GlobalXpub],
    kind: &str,
    index: Option<usize>,
    pairs: &[RawPair],
    findings: &mut Vec<Value>,
    truncated: &mut bool,
    saw_incomplete: &mut bool,
    saw_problem: &mut bool,
) {
    for pair in pairs {
        if pair.key.is_empty() {
            continue;
        }
        let type_byte = pair.key[0];
        let origin = match (kind, type_byte) {
            ("input", 0x06) | ("output", 0x02) => parse_origin(&pair.value),
            ("input", 0x16) | ("output", 0x07) => tap_origin(&pair.value),
            _ => continue,
        };
        check_one_derivation(
            secp,
            xpubs,
            kind,
            index,
            pair,
            origin,
            findings,
            truncated,
            saw_incomplete,
            saw_problem,
        );
    }
}

pub(crate) fn analyze(
    globals: &[RawPair],
    inputs: &[Vec<RawPair>],
    outputs: &[Vec<RawPair>],
) -> Value {
    let mut dup_findings = Vec::new();
    let mut dup_trunc = false;
    let (g, t) = duplicate_keys("global", None, globals);
    dup_findings.extend(g);
    dup_trunc |= t;
    for (i, map) in inputs.iter().enumerate() {
        let (f, t) = duplicate_keys("input", Some(i), map);
        for item in f {
            push(&mut dup_findings, &mut dup_trunc, item);
        }
        dup_trunc |= t;
    }
    for (j, map) in outputs.iter().enumerate() {
        let (f, t) = duplicate_keys("output", Some(j), map);
        for item in f {
            push(&mut dup_findings, &mut dup_trunc, item);
        }
        dup_trunc |= t;
    }
    let dup_state = if dup_findings.is_empty() {
        "complete"
    } else {
        "problem"
    };

    let secp = Secp256k1::verification_only();
    let xpubs = collect_xpubs(globals);
    let mut origin_findings = Vec::new();
    let mut origin_trunc = false;
    let mut saw_incomplete = false;
    let mut saw_problem = false;
    for (i, map) in inputs.iter().enumerate() {
        scan_derivations(
            &secp,
            &xpubs,
            "input",
            Some(i),
            map,
            &mut origin_findings,
            &mut origin_trunc,
            &mut saw_incomplete,
            &mut saw_problem,
        );
    }
    for (j, map) in outputs.iter().enumerate() {
        scan_derivations(
            &secp,
            &xpubs,
            "output",
            Some(j),
            map,
            &mut origin_findings,
            &mut origin_trunc,
            &mut saw_incomplete,
            &mut saw_problem,
        );
    }
    let origin_state = if saw_problem {
        "problem"
    } else if saw_incomplete {
        "incomplete"
    } else {
        "complete"
    };

    json!({
        "duplicateKeys": family(dup_state, dup_findings, dup_trunc),
        "xpubDerivesChild": family(origin_state, origin_findings, origin_trunc),
    })
}
