import { psbtInspectDoc } from "./psbt-wasm.js";

const hexToBytes = (hex) => {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error("invalid hexadecimal field");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

const concat = (...parts) => {
  const length = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(length);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.length;
  }
  return out;
};

const le32 = (n) => new Uint8Array([n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255]);

const varint = (value) => {
  const n = BigInt(value);
  if (n < 253n) return new Uint8Array([Number(n)]);
  if (n <= 0xffffn) return concat(new Uint8Array([253]), new Uint8Array([Number(n & 255n), Number((n >> 8n) & 255n)]));
  if (n <= 0xffffffffn) return concat(new Uint8Array([254]), new Uint8Array([Number(n & 255n), Number((n >> 8n) & 255n), Number((n >> 16n) & 255n), Number((n >> 24n) & 255n)]));
  const out = new Uint8Array(9);
  out[0] = 255;
  let x = n;
  for (let i = 1; i < 9; i++) { out[i] = Number(x & 255n); x >>= 8n; }
  return out;
};

const le64 = (value) => {
  let n = BigInt(value);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
};

const reverse = (bytes) => Uint8Array.from(bytes).reverse();

const finalFields = (map, name) => map.filter((pair) => pair.name === name);

const finalScripts = (map) => {
  const scriptSigFields = finalFields(map, "PSBT_IN_FINAL_SCRIPTSIG");
  const witnessFields = finalFields(map, "PSBT_IN_FINAL_SCRIPTWITNESS");
  if (scriptSigFields.length > 1 || witnessFields.length > 1) return null;
  const scriptSig = scriptSigFields[0];
  const witness = witnessFields[0];
  if (!scriptSig && !witness) return null;
  if (scriptSig?.decodeError || witness?.decodeError) return null;
  const scriptSigBytes = scriptSig ? hexToBytes(scriptSig.value) : new Uint8Array();
  const witnessItems = witness?.decoded?.items?.map(hexToBytes) ?? [];
  return { scriptSig: scriptSigBytes, witness: witnessItems };
};

const serializeFinalTx = (doc) => {
  if (doc.rustBitcoinError) return null;
  if (doc.inputs.some((map) => map.some((pair) => pair.decodeError))) return null;

  const inputs = doc.tx.inputs;
  const outputs = doc.tx.outputs;
  const finals = inputs.map((_, i) => finalScripts(doc.inputs[i]));
  if (finals.some((value) => value === null)) return null;

  const hasWitness = finals.some(({ witness }) => witness.length > 0);
  const version = le32(doc.tx.version >>> 0);
  const vin = inputs.map((input, i) => concat(
    reverse(hexToBytes(input.txid)),
    le32(input.vout),
    varint(finals[i].scriptSig.length),
    finals[i].scriptSig,
    le32(input.sequence >>> 0),
  ));
  const witnesses = hasWitness
    ? finals.map(({ witness }) => concat(varint(witness.length), ...witness.map((item) => concat(varint(item.length), item))))
    : [];
  const vout = outputs.map((output) => {
    const script = hexToBytes(output.scriptPubKey);
    return concat(le64(output.value), varint(script.length), script);
  });
  const locktime = le32(doc.tx.locktime >>> 0);
  return {
    base: concat(version, varint(vin.length), ...vin, varint(vout.length), ...vout, locktime),
    full: hasWitness
      ? concat(version, new Uint8Array([0, 1]), varint(vin.length), ...vin, varint(vout.length), ...vout, ...witnesses, locktime)
      : concat(version, varint(vin.length), ...vin, varint(vout.length), ...vout, locktime),
  };
};

const sumInputs = (doc) => {
  let total = 0n;
  for (const map of doc.inputs) {
    const amounts = map
      .filter((pair) => pair.name === "PSBT_IN_WITNESS_UTXO")
      .map((pair) => pair.decoded?.value)
      .filter((value) => typeof value === "string");
    const nonWitness = map.find((pair) => pair.name === "PSBT_IN_NON_WITNESS_UTXO");
    if (nonWitness?.decoded?.prevout?.value != null) amounts.push(nonWitness.decoded.prevout.value);
    if (!amounts.length) return null;
    const unique = [...new Set(amounts)];
    if (unique.length !== 1) return null;
    total += BigInt(unique[0]);
  }
  return total;
};

const sumOutputs = (doc) => doc.tx.outputs.reduce((sum, output) => sum + BigInt(output.value), 0n);

/**
 * Derives deterministic inspection facts from a decoded PSBT document.
 * Amounts are returned as decimal strings to preserve satoshi precision.
 * Exact weight/vsize are reported only when every input has a final
 * scriptSig and/or final scriptWitness, so incomplete PSBTs never receive an
 * estimated transaction size.
 */
export const psbtCostFactsFromDoc = (doc) => {
  const inputAmount = sumInputs(doc);
  const outputAmount = sumOutputs(doc);
  // honor inspector's monetary validity (MAX_MONEY, overflow, negative)
  const feeInvalid = Boolean(doc.fee?.error) || (doc.fee?.known && doc.fee?.sats == null);
  const rawFee = inputAmount !== null && inputAmount >= outputAmount ? inputAmount - outputAmount : null;
  const fee = feeInvalid ? null : rawFee;
  const tx = serializeFinalTx(doc);
  const finalized = tx !== null;
  const weight = finalized ? BigInt(tx.base.length * 3 + tx.full.length) : null;
  const vsize = weight === null ? null : (weight + 3n) / 4n;
  return {
    inputCount: doc.tx.inputs.length,
    outputCount: doc.tx.outputs.length,
    inputAmountSats: inputAmount === null ? null : inputAmount.toString(),
    outputAmountSats: outputAmount.toString(),
    feeSats: fee === null ? null : fee.toString(),
    finalized,
    weight: weight === null ? null : Number(weight),
    vsize: vsize === null ? null : Number(vsize),
    feeRateSatPerVbyte: fee === null || vsize === null || vsize === 0n ? null : Number(fee) / Number(vsize),
  };
};

/** Inspect raw PSBT bytes and derive exact cost facts. */
export const psbtCostFacts = (psbtBytes) => psbtCostFactsFromDoc(psbtInspectDoc(psbtBytes));