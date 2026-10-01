// The app's one clipboard writer. Every copy control hands its text here at
// the moment of the click (a secret is built for the copy and not kept on the
// control, #546 B3), and shows its own confirmation only when the promise
// says the clipboard really took the text.
//
// The Clipboard API is used when the page has it. Where it is missing or
// refuses (older browsers, some app views, file:// origins), a hidden
// read-only field carries the text just long enough for execCommand("copy"),
// then is emptied and removed, whether the copy worked or threw. A modal
// passes itself as `host` so the field, and the focus select() gives it,
// stay inside its focus trap.
const fallbackCopy = (text, host) => {
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("readonly", "");
  field.style.position = "fixed";
  field.style.left = "-9999px";
  host.append(field);
  field.select();
  try {
    return document.execCommand("copy") === true;
  } catch {
    return false;
  } finally {
    field.value = "";
    field.remove();
  }
};

export const copyText = async (text, { host = document.body } = {}) => {
  if (!text) return false;
  const writeText = navigator.clipboard?.writeText;
  if (typeof writeText === "function") {
    try {
      await writeText.call(navigator.clipboard, text);
      return true;
    } catch {}
  }
  return fallbackCopy(text, host);
};
