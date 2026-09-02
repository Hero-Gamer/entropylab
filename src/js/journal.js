// Offline session journal: notepad, session snapshot, debug log.
// In-memory only. No network, no browser storage, no CSPRNG.
export const JOURNAL_LOG_LIMIT = 400;

function pad2(n) {
  return String(n).padStart(2, "0");
}

export function formatStamp(date = new Date()) {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) return "";
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

export function createJournal() {
  return { nextId: 1, notes: [], log: [], stateText: "" };
}

export function addNote(journal, { at, text } = {}, now = new Date()) {
  let note = { id: journal.nextId++, at: at || formatStamp(now), text: String(text ?? "") };
  journal.notes.push(note);
  return note;
}

export function updateNote(journal, id, patch) {
  let note = journal.notes.find((entry) => entry.id === id);
  if (!note) return null;
  if (patch && Object.prototype.hasOwnProperty.call(patch, "at")) note.at = String(patch.at ?? "");
  if (patch && Object.prototype.hasOwnProperty.call(patch, "text")) note.text = String(patch.text ?? "");
  return note;
}

export function deleteNote(journal, id) {
  let index = journal.notes.findIndex((entry) => entry.id === id);
  if (index < 0) return false;
  journal.notes.splice(index, 1);
  return true;
}

export function formatNotes(notes) {
  if (!notes.length) return "No notes.";
  return notes.map((note, i) => `Note ${i + 1}\nWritten: ${note.at || "(no time)"}\n${note.text || ""}`.trimEnd()).join("\n\n---\n\n");
}

export function appendLog(journal, { at, tool, action, detail } = {}, now = new Date()) {
  journal.log.push({
    at: at || formatStamp(now),
    tool: String(tool || ""),
    action: String(action || ""),
    detail: String(detail || "").slice(0, 300),
  });
  while (journal.log.length > JOURNAL_LOG_LIMIT) journal.log.shift();
  return journal.log[journal.log.length - 1];
}

export function formatLog(events) {
  if (!events.length) return "No events yet.";
  return events.map((event) => {
    let detail = event.detail ? `  ${event.detail}` : "";
    return `${event.at}\t${event.tool}\t${event.action}${detail}`;
  }).join("\n");
}

export function snapshotSession(session) {
  let lines = [
    "ENTROPYLAB SESSION STATE",
    `Captured: ${session.capturedAt || ""}`,
    `Build: ${session.version || "unknown"}${session.commit ? ` · ${session.commit}` : ""}`,
    `Private material: ${session.includePrivate ? "INCLUDED" : "omitted"}`,
    "",
  ];
  lines.push("KEYS");
  if (!session.keys?.length) lines.push("(none)");
  else for (let key of session.keys) {
    if (!key.derived) {
      lines.push(`- ${key.name || "Key"} · not derived · method ${key.mode || "unknown"}`);
      continue;
    }
    lines.push(`- ${key.name || "Key"}${key.fingerprint ? ` · fingerprint ${key.fingerprint}` : ""}`);
    if (key.sheet) lines.push(key.sheet, "");
  }
  lines.push("", "MULTISIG");
  if (!session.msigs?.length) lines.push("(none)");
  else for (let msig of session.msigs) {
    if (!msig.derived) {
      lines.push(`- ${msig.name || "Multisig"} · not derived`);
      continue;
    }
    lines.push(`- ${msig.name || "Multisig"}${msig.summary ? ` · ${msig.summary}` : ""}`);
    if (msig.sheet) lines.push(msig.sheet, "");
  }
  lines.push("", "BIP-85");
  if (!session.bip85?.length) lines.push("(none)");
  else for (let child of session.bip85) {
    lines.push(`- ${child.name || "BIP-85"}${child.fingerprint ? ` · ${child.fingerprint}` : ""}${child.app ? ` · ${child.app}` : ""}${child.secret && session.includePrivate ? `\n  ${child.secret}` : ""}`);
  }
  lines.push("", "SILENT PAYMENTS");
  lines.push(session.sp?.derived ? `- fingerprint ${session.sp.fingerprint || "unknown"}${session.sp.address ? `\n  ${session.sp.address}` : ""}` : "- not derived");
  lines.push("", "PSBT");
  lines.push(session.psbt?.loaded ? "- payload present in the inspector" : "- inspector empty");
  lines.push("", "This snapshot lives in this page until you download it. Closing the tab discards it.");
  return lines.join("\n");
}

export function wipeJournal(journal) {
  journal.notes.forEach((note) => {
    note.text = "";
    note.at = "";
  });
  journal.notes.length = 0;
  journal.log.length = 0;
  journal.stateText = "";
  journal.nextId = 1;
  return journal;
}
