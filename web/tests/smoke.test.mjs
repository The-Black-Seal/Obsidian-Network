// A smoke test for the interface: does it boot, and does it render a real chain?
//
// Run with:  node --test web/tests/
//
// This runs js/app.js the way a browser does — an ES module, on a DOM, with
// `hashchange` and `DOMContentLoaded` — against a *live* node and explorer
// service.  It is the test that catches the failure nobody writes a unit test
// for: a page that throws on load and leaves a person staring at an empty screen.
//
// Node has no DOM, so this file provides a small one.  It implements exactly the
// surface the interface uses — elements, text, attributes, children, events,
// query selectors — and nothing else.  A shim that grew into a browser engine
// would stop being a fair test, which is why it is small and why the interface is
// written to use a small surface: it builds nodes instead of parsing HTML.
//
// Set OBSIDIAN_BASE_URL to point at a running deployment; the default is the
// local one the acceptance run starts.

import test from 'node:test';
import assert from 'node:assert/strict';

const BASE = process.env.OBSIDIAN_BASE_URL || 'http://127.0.0.1:8081';

import { installDom, installFetch, waitFor } from './dom.mjs';
import { stop } from '../js/state.js';

test('the interface boots against a live chain and renders it', async (t) => {
  // The page polls while it is open; a test is not a page, so it stops polling on
  // the way out rather than leaving node alive waiting for a timer.
  t.after(() => stop());

  // The services may not be running in every environment; a skip is honest,
  // a silent pass is not.
  let reachable = true;
  try {
    const response = await fetch(`${BASE}/node/api/v1/status`);
    reachable = response.ok;
  } catch (cause) {
    reachable = false;
  }
  if (!reachable) {
    t.skip(`no deployment at ${BASE}; start the node and obs-app first`);
    return;
  }

  installFetch(BASE);
  // The page's own markup, so the test runs against the document that is really
  // served — and fails if a view looks up an id the page no longer has.
  const page = await (await fetch(`${BASE}/`)).text();
  const { document, window, ids } = installDom({ html: page });

  // Importing app.js is what a browser does when it loads the page.
  await import('../js/app.js');
  document.dispatch('DOMContentLoaded', {});
  window.dispatch('hashchange', {});

  // The header learns which network it is on from the node itself.
  await waitFor(() => ids['net-name'].textContent && ids['net-name'].textContent !== 'connecting…');
  const badge = ids['net-name'].textContent;
  assert.match(badge, /devnet|testnet|staging|mainnet/, `unexpected network badge: ${badge}`);

  // The main region fills with the Mining view, which reads the chain's own
  // mining parameters — so its numbers come from the node, not from constants in
  // the page.
  await waitFor(() => ids['main'].children.length > 0);
  const rendered = ids['main'].textContent;
  assert.match(rendered, /Mining/);
  assert.match(rendered, /Proof of time|proof of time/);
  // The reward shown is the chain's, and it is a 12-decimal string, never a float.
  assert.match(rendered, /0\.000166666666|0\.0001666666/, 'the claim reward should come from the chain');
  // The interface must not describe the network as proof of work.
  assert.doesNotMatch(rendered, /hashrate|hash rate|mining rig|ASIC/i);

  // The footer carries the protocol's figures, read from the chain.
  await waitFor(() => /maximum supply/.test(ids['protocol-facts'].textContent));
  assert.match(ids['protocol-facts'].textContent, /21,000,000 OBS maximum supply/);

  // Every view must render.  A route that throws leaves the person on a page
  // that says "that did not work", which is a failure even though the service is
  // perfectly healthy — so each view is visited and its heading checked.
  const views = [
    ['mining', /Mining/],
    ['wallet', /Wallet/],
    ['explorer', /Explorer/],
    ['developers', /Developer Portal/],
  ];
  for (const [name, heading] of views) {
    window.location.hash = `#/${name}`;
    window.dispatch('hashchange', {});
    await waitFor(() => heading.test(ids['main'].textContent));
    assert.equal(
      ids['toast'].hidden,
      true,
      `the ${name} view reported an error: ${ids['toast'].textContent}`,
    );
    const text = ids['main'].textContent;
    assert.ok(text.length > 200, `the ${name} view rendered almost nothing`);
    // No view may describe the network as proof of work.
    assert.doesNotMatch(text, /hashrate|hash rate|mining rig|ASIC/i, `the ${name} view mentions proof of work`);
  }

  // The privacy contract, checked against what is actually on the screen: the
  // Explorer and the portal show a partial address and never a whole one.  (The
  // Wallet view is the exception by design — it shows the person their own
  // address, because it is theirs.)
  for (const name of ['explorer', 'developers']) {
    window.location.hash = `#/${name}`;
    window.dispatch('hashchange', {});
    await waitFor(() => ids['main'].children.length > 0);
    await new Promise((resolve) => setTimeout(resolve, 400));
    const text = ids['main'].textContent;
    const whole = text.match(/\b(?:obs1|dobs1|tobs1|sobs1)[a-z0-9]{30,}/);
    assert.equal(whole, null, `the ${name} view showed a whole address: ${whole && whole[0]}`);
    assert.doesNotMatch(text, /\bbalance\b\s*[:=]\s*[0-9]/i, `the ${name} view rendered a balance`);
  }

  // ---------------------------------------------------------------------------
  // The wallet, end to end, in the page.
  //
  // This is the test that matters most: it drives the real Rust module — the same
  // one the command-line client uses — through the interface, and checks that a
  // person can create a wallet and that nothing secret reaches the screen.
  // ---------------------------------------------------------------------------
  window.location.hash = '#/wallet';
  window.dispatch('hashchange', {});
  await waitFor(() => /Create a wallet/.test(ids['main'].textContent));

  const clickButton = (label) => {
    const found = ids['main'].querySelectorAll('button')
      .find((candidate) => new RegExp(label, 'i').test(candidate.textContent));
    assert.ok(found, `no "${label}" button on the wallet view`);
    found.dispatch('click');
    return found;
  };

  clickButton('Create a wallet');
  const phraseGrid = await waitFor(() => ids['main'].querySelector('.phrase-grid'));
  await waitFor(() => phraseGrid.children.length === 24);
  assert.equal(phraseGrid.children.length, 24, 'a wallet is 24 words');

  // The words are the wallet and are shown once; what must never appear is key
  // material.  A private key here is 64 hex characters, so the screen must not
  // contain one.
  const afterCreate = ids['main'].textContent;
  assert.equal(afterCreate.match(/\b[0-9a-f]{64}\b/g), null, 'a raw key reached the screen');

  // Seal it with a password, the way a person would.
  const passwords = ids['main'].querySelectorAll('input')
    .filter((field) => field.getAttribute('name') === 'password'
      || field.getAttribute('name') === 'confirm');
  assert.equal(passwords.length, 2, 'the create form asks for a password and a confirmation');
  for (const field of passwords) field.value = 'a-long-enough-password';

  clickButton('Save the keystore');
  // Argon2id sealing is deliberately slow; this is the one wait that is measured
  // in seconds rather than milliseconds.
  await waitFor(() => globalThis.localStorage.getItem('obsidian.keystore'), { timeout: 30000 });

  // The sealed keystore is the Rust format: base64url text, no plaintext key.
  const sealed = globalThis.localStorage.getItem('obsidian.keystore');
  assert.match(sealed, /^[A-Za-z0-9_-]{100,}$/, 'the keystore should be sealed base64url text');
  assert.equal(/[0-9a-f]{64}/.test(sealed), false, 'the sealed keystore contains a raw key');

  // The wallet announces its address once it is sealed.  The address is the
  // wallet's to show — it is the person's own — so it must appear, and the key it
  // came from must not.
  const announced = await waitFor(() => {
    const found = ids['toast'].textContent.match(/(?:dobs1|obs1)[a-z0-9]{20,}/);
    return found && found[0];
  });
  assert.match(announced, /^(?:dobs1|obs1)/);

  // Now reload the page the way a person would: the session is gone, the sealed
  // keystore is all that is left in the browser, and the wallet must open from it.
  // This is the check that the sealed text is really the Rust keystore format and
  // not something only this session could read.
  ids['toast'].textContent = '';
  document.dispatch('DOMContentLoaded', {});
  window.dispatch('hashchange', {});
  const reopened = await waitFor(() => (
    ids['main'].textContent.includes(announced) ? ids['main'].textContent : null
  ));
  assert.match(reopened, /Address/, 'the reopened wallet shows its address');
  assert.equal(reopened.match(/\b[0-9a-f]{64}\b/g), null, 'a raw key reached the screen');
  // The reopened wallet is locked for spending until the password is given, and
  // the interface must say so rather than pretend it can sign.
  assert.match(ids['main'].textContent, /unlock|Locked|locked/i, 'the reopened wallet should be locked');

  // Unlock it with the password it was sealed with.  This is the round trip that
  // proves the sealed text really is a Rust keystore: the same password, the same
  // address coming back out, and a wallet the module will sign with.
  const unlockPassword = ids['main'].querySelectorAll('input')
    .find((field) => field.getAttribute('name') === 'unlock-password');
  assert.ok(unlockPassword, 'the locked wallet should ask for its password');
  unlockPassword.value = 'a-long-enough-password';
  clickButton('Unlock');
  await waitFor(() => ids['main'].textContent.includes('Lock this wallet'), { timeout: 30000 });
  assert.match(ids['main'].textContent, /Your wallet/, 'the unlocked wallet is open');
  assert.equal(
    ids['main'].textContent.match(/\b[0-9a-f]{64}\b/g),
    null,
    'a raw key reached the screen after unlocking',
  );

  // The wallet asks the chain about itself, proving the key rather than naming an
  // address.  This wallet was created a moment ago and holds no invitation, so the
  // chain answers "no such account" — which is the honest answer, and the one the
  // interface must show.  What it must never do is invent a balance of zero.
  await waitFor(
    () => !/Reading the account's state/.test(ids['main'].textContent),
    { timeout: 20000 },
  );
  const settled = ids['main'].textContent;
  assert.match(settled, /not on chain yet/i, 'an unregistered wallet must be reported as such');
  assert.doesNotMatch(
    settled,
    /Reading the account's state/,
    'the balance card must resolve rather than stay pending',
  );
  // It asked the chain and the chain answered "no such account"; a wallet with no
  // account must never be shown a number the chain did not send.
  assert.doesNotMatch(settled, /Lifetime rewards/, 'no balance may be invented for an unknown account');

  // And the interface cannot mint.  A claim signed by an account the chain does
  // not know must be refused by the node — the page has no way to make the chain
  // accept it, which is the authority rule this whole system is built on.
  ids['toast'].textContent = '';
  ids['toast'].className = '';
  clickButton('Mine a claim');
  const refused = await waitFor(() => (ids['toast'].textContent ? ids['toast'].textContent : null), {
    timeout: 20000,
  });
  // Whatever the wording, the page must not report a claim it cannot make, and
  // the message must be a failure rather than a success.
  assert.match(ids['toast'].className, /bad/, `expected a failure toast, got "${refused}"`);
  assert.doesNotMatch(
    refused,
    /Claim signed and submitted/i,
    'an account the chain does not know must not be able to claim',
  );
});
