// A domestic-size DOM, used by the interface's tests.
//
// Node has no DOM, so this is a small one: elements, text, attributes, children,
// events, query selectors — exactly the surface the interface uses, because the
// interface builds nodes instead of parsing HTML.  It lives in its own file so
// the smoke test and any ad-hoc check can share it without importing a test.
//
// A shim that grew into a browser engine would stop being a fair test; this one
// stays deliberately small.

export const DEFAULT_BASE = 'http://127.0.0.1:8081';

export class Text {
  constructor(data) { this.data = String(data); }
  get textContent() { return this.data; }
}

export class Element {
  constructor(tag) {
    this.tagName = String(tag).toLowerCase();
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.dataset = {};
    this._text = '';
    this.className = '';
    this.hidden = false;
    this.checked = false;
    this.value = '';
  }
  get textContent() {
    if (this.children.length) return this.children.map((child) => child.textContent).join('');
    return this._text;
  }
  set textContent(value) { this.children = []; this._text = String(value); }
  get childCount() { return this.children.length; }
  append(...nodes) {
    for (const node of nodes) {
      if (node === null || node === undefined) continue;
      this.children.push(node);
      this._text = '';
    }
  }
  replaceChildren(...nodes) { this.children = []; this._text = ''; this.append(...nodes); }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === 'class') this.className = String(value);
    if (name === 'hidden') this.hidden = true;
    if (name.startsWith('data-')) this.dataset[name.slice(5)] = String(value);
  }
  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === 'hidden') this.hidden = false;
  }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  toggleAttribute(name, force) {
    const on = force === undefined ? !this.attributes.has(name) : Boolean(force);
    if (on) this.setAttribute(name, ''); else this.removeAttribute(name);
    return on;
  }
  addEventListener(type, handler) {
    const list = this.listeners.get(type) || [];
    list.push(handler);
    this.listeners.set(type, list);
  }
  dispatch(type, event = {}) {
    for (const handler of this.listeners.get(type) || []) handler({ type, ...event });
  }
  focus() {}
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    // Four selector shapes, which is all the interface uses: `#id`, `.class`,
    // `tag`, and `tag.class` (the last one because `img.mark` is how the header's
    // logo is found).  A shim that supported CSS would stop being a fair test.
    const match = (node) => {
      if (selector.startsWith('#')) {
        return Boolean(node.getAttribute) && node.getAttribute('id') === selector.slice(1);
      }
      let tag = null;
      let rest = selector;
      const dot = selector.indexOf('.');
      if (dot > 0) {
        tag = selector.slice(0, dot).toLowerCase();
        rest = selector.slice(dot);
      }
      if (rest.startsWith('.')) {
        const wanted = rest.slice(1).split('.').filter(Boolean);
        const classes = String(node.className || '').split(/\s+/).filter(Boolean);
        if (!wanted.every((name) => classes.includes(name))) return false;
        return tag === null || node.tagName === tag;
      }
      return node.tagName === selector.toLowerCase();
    };
    const found = [];
    const walk = (node) => {
      for (const child of node.children || []) {
        if (child instanceof Element) {
          if (match(child)) found.push(child);
          walk(child);
        }
      }
    };
    walk(this);
    return found;
  }
  scrollIntoView() {}
}

/** A DOM small enough to read and big enough to run this interface. */
export function installDom({ hash = '#/mining', html = '' } = {}) {
  const ids = {};
  for (const id of ['main', 'net-badge', 'net-name', 'offline', 'offline-detail', 'protocol-facts', 'toast']) {
    const node = new Element('div');
    node.setAttribute('id', id);
    // When the caller passes the page's own markup, a starting state marked
    // `hidden` in the document starts hidden here too.  Without this the shim
    // would invent a visible toast and a visible "the node is not answering"
    // banner, and the tests would be checking a page nobody sees.
    if (html) {
      const tag = html.match(new RegExp(`<[^>]*id="${id}"[^>]*>`));
      if (tag && /\shidden(\s|>|=)/.test(tag[0])) node.hidden = true;
    }
    ids[id] = node;
  }
  const windowListeners = new Map();
  const document = {
    title: '',
    hidden: false,
    body: new Element('body'),
    documentElement: new Element('html'),
    getElementById: (id) => ids[id] || null,
    createElement: (tag) => new Element(tag),
    createTextNode: (text) => new Text(text),
    querySelector: (selector) => document.body.querySelector(selector)
      || new Element('div'),
    querySelectorAll: (selector) => document.body.querySelectorAll(selector),
    listeners: new Map(),
    addEventListener(type, handler) {
      const list = document.listeners.get(type) || [];
      list.push(handler);
      document.listeners.set(type, list);
    },
    dispatch(type, event = {}) {
      for (const handler of document.listeners.get(type) || []) handler({ type, ...event });
      // In a browser these events bubble to `window`, and the interface — like
      // most pages — listens for `DOMContentLoaded` there.  A shim that dropped
      // that detail would let a page that never boots pass its tests.
      for (const handler of windowListeners.get(type) || []) handler({ type, ...event });
    },
  };
  const window = {
    location: { hash, reload() {} },
    scrollTo() {},
    addEventListener(type, handler) {
      const list = windowListeners.get(type) || [];
      list.push(handler);
      windowListeners.set(type, list);
    },
    dispatch(type, event = {}) {
      for (const handler of windowListeners.get(type) || []) handler({ type, ...event });
    },
  };
  const store = new Map();
  const localStorage = {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => { store.set(key, String(value)); },
    removeItem: (key) => { store.delete(key); },
    clear: () => store.clear(),
    key: (index) => [...store.keys()][index] ?? null,
    get length() { return store.size; },
  };
  globalThis.window = window;
  globalThis.localStorage = localStorage;
  // `URL.createObjectURL` is how the wallet offers its keystore as a download;
  // Node has `URL` but not that method.
  globalThis.URL = globalThis.URL || class URL {};
  if (!globalThis.URL.createObjectURL) globalThis.URL.createObjectURL = () => 'blob:shim';
  if (!globalThis.URL.revokeObjectURL) globalThis.URL.revokeObjectURL = () => {};
  globalThis.document = document;
  globalThis.HTMLElement = Element;
  globalThis.location = window.location;
  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  return { document, window, ids };
}


/** Fetches the way the page does: a relative path, resolved against `base`. */
export function installFetch(base = DEFAULT_BASE) {
  const original = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    // A browser resolves a relative URL against the document's origin: `/x` and
    // `x`, `/x?y` and `#fragment` all arrive at the server as absolute URLs.  The
    // shim resolves them the same way, so a page that asks for
    // `wasm/obsidian-wallet.wasm` gets it.
    let url = input;
    if (typeof url === 'string' && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
      url = new globalThis.URL(url.replace(/^\//, ''), `${base}/`).toString();
    }
    return original(url, init);
  };
  return original;
}

/** Waits for a condition, failing loudly rather than hanging forever. */
export async function waitFor(check, { timeout = 15000, interval = 50 } = {}) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  throw new Error('the interface did not reach the expected state in time');
}
