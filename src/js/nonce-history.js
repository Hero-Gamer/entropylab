import { sha256 } from "./hashes.js";

export const NONCE_HISTORY_FORMAT = "entropylab-nonce-history";
export const NONCE_HISTORY_VERSION = 1;
export const NONCE_HISTORY_MAX_RECORDS = 10000;
export const NONCE_HISTORY_MAX_TEXT = 5000000;

const encoder = new TextEncoder();
const hexPattern = /^[0-9a-f]{64}$/;

function concatBytes(first, second) {
  const out = new Uint8Array(first.length + second.length);
  out.set(first);
  out.set(second, first.length);
  return out;
}

function hex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function taggedIdentity(label, bytes) {
  if (!(bytes instanceof Uint8Array) || !bytes.length) throw new Error(`Nonce history ${label} must be bytes.`);
  return hex(sha256(concatBytes(encoder.encode(`EntropyLab nonce history ${label} v1\0`), bytes)));
}

function checkedAt(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error("Nonce history checkedAt values must be ISO 8601 UTC timestamps.");
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error("Nonce history contains an invalid checkedAt timestamp.");
  }
  return value;
}

function normalizeRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new Error("Nonce history contains an invalid record.");
  const allowed = new Set(["checkedAt", "masterFingerprint", "keyTag", "r", "messageTag", "verified"]);
  if (Object.keys(record).some((key) => !allowed.has(key))) {
    throw new Error("Nonce history records contain unsupported fields.");
  }
  if (record.masterFingerprint !== null && !/^[0-9a-f]{8}$/.test(record.masterFingerprint || "")) {
    throw new Error("Nonce history master fingerprints must be null or 8 lowercase hexadecimal characters.");
  }
  if (!hexPattern.test(record.keyTag || "")) {
    throw new Error("Nonce history key tags must be 32-byte lowercase hex values.");
  }
  if (!hexPattern.test(record.r || "")) {
    throw new Error("Nonce history r values must be 32-byte lowercase hex values.");
  }
  if (record.messageTag !== null && !hexPattern.test(record.messageTag || "")) {
    throw new Error("Nonce history message tags must be null or 32-byte lowercase hex values.");
  }
  if (typeof record.verified !== "boolean") throw new Error("Nonce history verified flags must be true or false.");
  return {
    checkedAt: checkedAt(record.checkedAt),
    masterFingerprint: record.masterFingerprint,
    keyTag: record.keyTag,
    r: record.r,
    messageTag: record.messageTag,
    verified: record.verified,
  };
}

function identity(record) {
  return `${record.keyTag}:${record.r}:${record.messageTag || ""}`;
}

export function nonceHistoryRecord({ checkedAt: inspectedAt = new Date().toISOString(), masterFingerprint = null, pubkey, r, sighash, context, valid } = {}) {
  const hasMessage = sighash instanceof Uint8Array && sighash.length > 0;
  if (!(pubkey instanceof Uint8Array) || pubkey.length !== 33 || (pubkey[0] !== 2 && pubkey[0] !== 3)) {
    throw new Error("Nonce history public keys must be compressed secp256k1 keys.");
  }
  if (!(r instanceof Uint8Array) || r.length !== 32) throw new Error("Nonce history r values must be 32 bytes.");
  if (hasMessage && sighash.length !== 32) throw new Error("Nonce history message digests must be 32 bytes.");
  if (!hasMessage && (!(context instanceof Uint8Array) || !context.length)) throw new Error("Nonce history needs a message digest or source context.");
  return normalizeRecord({
    checkedAt: inspectedAt,
    masterFingerprint,
    keyTag: taggedIdentity("key", pubkey),
    r: hex(r),
    messageTag: hasMessage ? taggedIdentity("message", sighash) : context instanceof Uint8Array && context.length ? taggedIdentity("context", context) : null,
    verified: valid === true && hasMessage,
  });
}

export function mergeNonceHistory(...groups) {
  const merged = new Map();
  for (const group of groups) {
    if (!Array.isArray(group)) throw new Error("Nonce history records must be an array.");
    for (const candidate of group) {
      const record = normalizeRecord(candidate), key = identity(record), previous = merged.get(key);
      if (previous) {
        previous.verified ||= record.verified;
        if (record.checkedAt < previous.checkedAt) previous.checkedAt = record.checkedAt;
        if (previous.masterFingerprint === null) previous.masterFingerprint = record.masterFingerprint;
        else if (record.masterFingerprint !== null && previous.masterFingerprint !== record.masterFingerprint) previous.masterFingerprint = null;
      } else merged.set(key, record);
      if (merged.size > NONCE_HISTORY_MAX_RECORDS) throw new Error(`Nonce history is limited to ${NONCE_HISTORY_MAX_RECORDS} records.`);
    }
  }
  return [...merged.values()];
}

export function compareNonceHistory(current, historical) {
  const now = mergeNonceHistory(current), before = mergeNonceHistory(historical);
  const byR = new Map();
  for (const record of before) {
    if (!byR.has(record.r)) byR.set(record.r, new Map());
    const keys = byR.get(record.r);
    if (!keys.has(record.keyTag)) keys.set(record.keyTag, { records: new Map(), verified: new Map() });
    const group = keys.get(record.keyTag);
    group.records.set(record.messageTag, record);
    if (record.verified && record.messageTag) group.verified.set(record.messageTag, record);
  }
  const otherThan = (map, messageTag) => {
    for (const [tag, record] of map) if (tag !== messageTag) return record;
    return null;
  };
  const reused = [], possible = [], crossKey = [];
  for (const present of now) {
    const keys = byR.get(present.r);
    if (!keys) continue;
    for (const [keyTag, group] of keys) {
      if (keyTag !== present.keyTag) {
        crossKey.push([present, group.records.values().next().value]);
        break;
      }
    }
    const sameKey = keys.get(present.keyTag);
    if (!sameKey) continue;
    const verifiedPrior = present.verified && present.messageTag ? otherThan(sameKey.verified, present.messageTag) : null;
    if (verifiedPrior) reused.push([present, verifiedPrior]);
    else {
      const uncertainPrior = otherThan(sameKey.records, present.messageTag);
      if (uncertainPrior) possible.push([present, uncertainPrior]);
    }
  }
  return { reused, possible, crossKey };
}

export function serializeNonceHistory(records) {
  return JSON.stringify({
    format: NONCE_HISTORY_FORMAT,
    version: NONCE_HISTORY_VERSION,
    records: mergeNonceHistory(records),
  }, null, 2) + "\n";
}

export function parseNonceHistory(text) {
  const value = String(text ?? "");
  if (!value.trim()) throw new Error("Nonce history file is empty.");
  if (value.length > NONCE_HISTORY_MAX_TEXT) throw new Error("Nonce history file is too large.");
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Nonce history file is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Nonce history file must contain an object.");
  const allowed = new Set(["format", "version", "records"]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) throw new Error("Nonce history file contains unsupported fields.");
  if (parsed.format !== NONCE_HISTORY_FORMAT || parsed.version !== NONCE_HISTORY_VERSION) {
    throw new Error("Unsupported nonce history format or version.");
  }
  if (!Array.isArray(parsed.records)) throw new Error("Nonce history file must contain a records array.");
  if (parsed.records.length > NONCE_HISTORY_MAX_RECORDS) throw new Error(`Nonce history is limited to ${NONCE_HISTORY_MAX_RECORDS} records.`);
  return mergeNonceHistory(parsed.records);
}
