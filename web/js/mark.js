// Which mark the header shows.
//
// The official logo is normally a file this deployment serves from its own
// origin (`assets/logo-official.png`), and this module does nothing at all.  Two
// other arrangements exist, and only one of them concerns this file:
//
//   * the operator configures `--logo-source <url>`: the *service* fetches the
//     mark and serves it from its own origin.  The browser never learns the URL,
//     and this file does nothing — it sees the same relative path either way.
//
//   * the operator configures `--mark-url <url>`: the service cannot reach the
//     host (a sandbox, a proxy allowlist, an air-gapped node) but the deployment's
//     visitors can.  The service publishes that URL at `assets/mark.json` and the
//     browser loads it directly.  That URL is then public — anyone who reads this
//     configuration learns it — which is why it is an operator's explicit choice
//     and never the default, and why the drawn seal in `assets/logo.svg` remains
//     the fallback if the host cannot be reached from the browser either.
//
// Deciding nothing is the point: this module moves a src attribute.  It has no
// say over money, keys, consensus or state, like the rest of the interface.

// The relative path the service serves its mark configuration from.
export const MARK_CONFIG = 'assets/mark.json';

// Where the page falls back to when a mark cannot be loaded.
export const FALLBACK = 'assets/logo.svg';

// Puts `config`'s URL on every mark in `document`, if it names one.
//
// Split out from the fetch so it can be tested without a network or a browser:
// given a document with marks, it either moves them or it does not.
export function applyMark(config, document) {
  const url = config && config.configured ? config.url : null;
  if (typeof url !== 'string' || url.length === 0) {
    return false;
  }
  for (const image of document.querySelectorAll('img.mark')) {
    image.setAttribute('src', url);
    // If that host is unreachable from this browser too, the page still has the
    // seal that ships with it.  Set once, so a broken fallback cannot loop.
    image.setAttribute('onerror', `this.onerror=null;this.src='${FALLBACK}';`);
  }
  const icon = document.querySelector('link[rel="icon"]');
  if (icon) {
    icon.setAttribute('href', url);
  }
  return true;
}

// Asks the service which mark to show and applies the answer.
//
// Called on load.  A failure here is silent by design: a page whose logo host is
// unreachable is a page with the drawn seal, not a page with an error.
export async function refreshMark({ document, fetchImpl } = {}) {
  const doc = document || (typeof globalThis.document !== 'undefined' ? globalThis.document : null);
  const doFetch = fetchImpl || (typeof fetch !== 'undefined' ? fetch : null);
  if (!doc || !doFetch) {
    return false;
  }
  try {
    const response = await doFetch(MARK_CONFIG, { cache: 'no-store' });
    if (!response.ok) {
      return false;
    }
    return applyMark(await response.json(), doc);
  } catch {
    return false;
  }
}

if (typeof globalThis.document !== 'undefined' && typeof globalThis.window !== 'undefined') {
  const start = () => {
    void refreshMark();
  };
  if (globalThis.document.readyState === 'loading') {
    globalThis.document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
}
