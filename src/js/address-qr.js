// Per-address QR codes. Every row of an address table gets a compact QR
// button so any derived address — not just the first one — can be verified
// by scanning it with a signing device, instead of retyping 42 characters
// on an air-gapped machine.
//
// The pattern mirrors expandable.js: the button markup is a pure function
// unit-tested under Node; initAddressQr is the only DOM entry point and
// keeps no state besides the one shared overlay. Buttons carry the address
// in a data attribute, so virtualized table re-renders never leave stale
// registry entries behind.

import { t } from "./i18n.js";
import { trapModalFocus } from "./modal-focus.js";

// An address or an xpub reads in full; a PSBT export does not, so anything
// past this length shows head and tail around an ellipsis. The code and the
// copy control still carry every byte.
const DISPLAY_LIMIT = 256;
const shortenMiddle = (value, head = 32, tail = 20) =>
  value.length > head + tail + 1 ? `${value.slice(0, head)}\u2026${value.slice(-tail)}` : value;

const escapeHtml = (text) =>
  String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

// Row markup: a small button rendered next to the address text. `label`
// names the address ("Address #3") for the overlay title and the aria-label.
// Addresses are public data, so the button is also shown in tables that
// include a WIF column — but it only ever encodes the address.
export const addressQrButtonHtml = (address, label, { animate = "" } = {}) => {
  const value = String(address ?? "");
  if (!value) return "";
  const caption = String(label ?? "") || value;
  // `animate` names a payload kind the overlay can ask its frames provider to
  // split — a PSBT past a single code's capacity becomes a UR sequence rather
  // than losing bytes or losing its button.
  const animated = animate ? ` data-address-qr-animate="${escapeHtml(animate)}"` : "";
  return `<button type="button" class="addr-qr no-print" data-address-qr="${escapeHtml(value)}" data-address-qr-label="${escapeHtml(caption)}"${animated} aria-label="${escapeHtml(t("Show QR code for {label}", { label: caption }))}">${escapeHtml(t("QR"))}</button>`;
};

// One shared overlay for every address table. `renderQr` is injected by the
// caller (app.js passes its hodlQrSvg) so the QR options — error correction,
// colors, size — stay defined next to every other QR the app renders. The
// copy and copied icons come in the same way, so the address copy control
// wears the glyphs every other copy button in the app does.
export const initAddressQr = (renderQr, icons = {}, { frames = null } = {}) => {
  if (typeof renderQr !== "function" || document.getElementById("addr-qr-overlay")) return;
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay addr-qr-overlay no-print";
  overlay.id = "addr-qr-overlay";
  overlay.hidden = true;
  // The address text and the icon after it both copy. Only the icon takes a
  // tab stop, so a keyboard reaches one copy control, not two. The icon turning
  // to a check is the visible confirmation; the note speaks it, unseen, so the
  // centred address never shifts.
  overlay.innerHTML = `
    <div class="modal-card addr-qr-card" role="dialog" aria-modal="true" aria-labelledby="addr-qr-title">
      <p class="modal-title addr-qr-title" id="addr-qr-title"></p>
      <div class="qr addr-qr-image" id="addr-qr-image"></div>
      <p class="field-note addr-qr-note" id="addr-qr-note" aria-live="polite"></p>
      <p class="addr-qr-address-row">
        <button type="button" class="mono addr-qr-address" id="addr-qr-address" tabindex="-1"></button>
        <button type="button" class="copy-button addr-qr-copy" id="addr-qr-copy"></button>
        <span class="sr-only" id="addr-qr-copied" aria-live="polite"></span>
      </p>
      <div class="row addr-qr-actions">
        <button class="btn secondary" id="addr-qr-close" type="button"></button>
      </div>
    </div>`;
  document.body.append(overlay);
  const title = overlay.querySelector("#addr-qr-title"),
    image = overlay.querySelector("#addr-qr-image"),
    note = overlay.querySelector("#addr-qr-note"),
    text = overlay.querySelector("#addr-qr-address"),
    copyButton = overlay.querySelector("#addr-qr-copy"),
    copiedNote = overlay.querySelector("#addr-qr-copied"),
    closeButton = overlay.querySelector("#addr-qr-close");
  closeButton.textContent = t("Close");
  const copyLabel = t("Copy address"),
    copyIcon = icons.copy?.() ?? "",
    copiedIcon = icons.copied?.() ?? "";
  text.title = copyLabel;
  image.title = copyLabel;
  let button = null,
    payload = "", // the full value; the line above may show it shortened
    frameTimer = 0, // cycling a UR sequence, when the payload needs one
    copiedTimer = 0;

  const resetCopied = () => {
    clearTimeout(copiedTimer);
    copyButton.classList.remove("is-copied");
    copyButton.innerHTML = copyIcon;
    copyButton.setAttribute("aria-label", copyLabel);
    copyButton.title = copyLabel;
    copiedNote.textContent = "";
  };
  const showCopied = () => {
    copyButton.classList.add("is-copied");
    copyButton.innerHTML = copiedIcon;
    copyButton.setAttribute("aria-label", t("Copied"));
    copyButton.title = t("Copied");
    copiedNote.textContent = t("Copied");
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(resetCopied, 1600);
  };
  const copy = () => {
    const value = payload;
    if (!value) return;
    // Inside the dialog, so focus returns to the copy icon rather than
    // falling out of the overlay when the helper field is removed.
    const fallback = () => {
      const field = document.createElement("textarea");
      field.value = value;
      field.setAttribute("readonly", "");
      field.style.position = "fixed";
      field.style.left = "-9999px";
      overlay.append(field);
      field.select();
      try {
        if (document.execCommand("copy")) showCopied();
      } finally {
        field.remove();
        copyButton.focus({ preventScroll: true });
      }
    };
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") navigator.clipboard.writeText(value).then(showCopied, fallback);
    else fallback();
  };
  resetCopied();

  const close = () => {
    overlay.hidden = true;
    clearInterval(frameTimer);
    frameTimer = 0;
    note.textContent = "";
    image.replaceChildren(); // drop the rendered QR so a closed overlay holds no stale address
    payload = "";
    resetCopied();
    button?.focus({ preventScroll: true });
    button = null;
  };
  const open = (target) => {
    const value = target.dataset.addressQr ?? "";
    if (!value) return;
    button = target;
    clearInterval(frameTimer);
    frameTimer = 0;
    title.textContent = target.dataset.addressQrLabel || value;
    payload = value;
    text.textContent = value.length > DISPLAY_LIMIT ? shortenMiddle(value) : value;
    // A payload the provider splits is scanned as a sequence: one code could
    // not hold it, and a truncated code would hand the signer a broken file.
    const kind = target.dataset.addressQrAnimate || "";
    const parts = kind && typeof frames === "function" ? frames(value, kind) : null;
    if (Array.isArray(parts) && parts.length > 1) {
      let frame = 0;
      const draw = () => {
        image.innerHTML = renderQr(parts[frame]);
        note.textContent = t("Animated UR · part {n} of {total}. Keep scanning until your signer has every part.", { n: frame + 1, total: parts.length });
        frame = (frame + 1) % parts.length;
      };
      draw();
      frameTimer = setInterval(draw, 600);
    } else {
      note.textContent = "";
      try {
        image.innerHTML = renderQr(value);
      } catch {
        image.replaceChildren();
        note.textContent = t("This value is too large for a single QR code.");
      }
    }
    resetCopied();
    overlay.hidden = false;
    closeButton.focus();
  };

  trapModalFocus(overlay, () => [text, copyButton, closeButton]);
  document.addEventListener("click", (event) => {
    const target = event.target.closest?.("[data-address-qr]");
    if (target) open(target);
  });
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) close();
  });
  overlay.addEventListener("keydown", (event) => {
    if (event.key === "Escape") close();
  });
  closeButton.addEventListener("click", close);
  text.addEventListener("click", copy);
  copyButton.addEventListener("click", copy);
  image.addEventListener("click", copy);
};
