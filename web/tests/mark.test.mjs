// Tests for the mark loader: does the page pick up an operator's browser-visible
// mark, and does it leave a deployment that has none alone?
//
// The two things worth pinning are the ones that would be a security or branding
// mistake rather than a cosmetic one: a configuration with no URL must not touch
// the page at all, and a mark that cannot be loaded must end at the seal that
// ships with the deployment.

import test from 'node:test';
import assert from 'node:assert/strict';

import { applyMark, refreshMark, FALLBACK } from '../js/mark.js';

// The smallest document that has what the loader touches.  `setAttribute` is the
// surface the real one uses, so the fake implements exactly that and records it.
function fakeDocument({ marks = 1, icon = true } = {}) {
  const images = [];
  for (let index = 0; index < marks; index += 1) {
    const attributes = new Map([['src', 'assets/logo-official.png']]);
    images.push({
      attributes,
      setAttribute: (name, value) => attributes.set(name, value),
      getAttribute: (name) => (attributes.has(name) ? attributes.get(name) : null),
    });
  }
  const linkAttributes = new Map([['href', 'assets/logo-official.png']]);
  const link = {
    attributes: linkAttributes,
    setAttribute: (name, value) => linkAttributes.set(name, value),
    getAttribute: (name) => (linkAttributes.has(name) ? linkAttributes.get(name) : null),
  };
  return {
    images,
    link,
    querySelectorAll: (selector) => (selector === 'img.mark' ? images : []),
    querySelector: (selector) => (icon && selector === 'link[rel="icon"]' ? link : null),
  };
}

test('an unconfigured deployment is left exactly as it is', () => {
  const document = fakeDocument();
  const before = document.images[0].getAttribute('src');

  assert.equal(applyMark({ configured: false, url: null }, document), false);
  assert.equal(document.images[0].getAttribute('src'), before);
  assert.equal(document.link.getAttribute('href'), before);

  // A document that claims to be configured but names nothing is the same case:
  // an empty attribute would blank the mark rather than fall back to the seal.
  assert.equal(applyMark({ configured: true, url: '' }, document), false);
  assert.equal(applyMark(null, document), false);
  assert.equal(document.images[0].getAttribute('src'), before);
});

test('a configured mark is applied to every mark and to the icon', () => {
  const document = fakeDocument({ marks: 2 });
  const url = 'https://mark.example/official.png';

  assert.equal(applyMark({ configured: true, url }, document), true);
  for (const image of document.images) {
    assert.equal(image.getAttribute('src'), url);
    // The fallback is set, so a host that is unreachable from this browser ends
    // at the seal that ships rather than at a broken image.
    assert.match(image.getAttribute('onerror'), /assets\/logo\.svg/);
  }
  assert.equal(document.link.getAttribute('href'), url);
});

test('a deployment that requires no mark fetch does not ask for one', async () => {
  const document = fakeDocument();
  const calls = [];
  const fetchImpl = async (path, options) => {
    calls.push([path, options && options.cache]);
    return { ok: true, json: async () => ({ configured: false, url: null }) };
  };

  assert.equal(await refreshMark({ document, fetchImpl }), false);
  assert.deepEqual(calls, [['assets/mark.json', 'no-store']]);
  assert.equal(document.images[0].getAttribute('src'), 'assets/logo-official.png');
});

test('an unreachable or malformed configuration leaves the page alone', async () => {
  const document = fakeDocument();

  // The service is down, or answers with something that is not JSON.
  assert.equal(
    await refreshMark({
      document,
      fetchImpl: async () => {
        throw new Error('offline');
      },
    }),
    false,
  );
  assert.equal(
    await refreshMark({
      document,
      fetchImpl: async () => ({
        ok: true,
        json: async () => {
          throw new Error('not json');
        },
      }),
    }),
    false,
  );
  // A non-200 answer is not a configuration either.
  assert.equal(
    await refreshMark({ document, fetchImpl: async () => ({ ok: false, json: async () => ({}) }) }),
    false,
  );
  assert.equal(document.images[0].getAttribute('src'), 'assets/logo-official.png');
  assert.equal(FALLBACK, 'assets/logo.svg');
});
