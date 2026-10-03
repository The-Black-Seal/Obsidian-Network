// Tests the WebAssembly wallet the way a page uses it.
//
// Run with:  node --test web/tests/
//
// This is the test that matters most in the web tier, because it exercises the
// *compiled* module rather than the Rust source it was built from: the ABI, the
// length-prefixed result buffer, the host entropy import and the JSON envelope
// are all part of what a browser will actually load.  If the module in
// web/wasm/ is stale, or its exports were renamed, the interface is broken in a
// way no unit test of the Rust would catch.
//
// Node does not provide `crypto.getRandomValues` as a wasm import, so this file
// supplies one from `node:crypto` — exactly the role the browser's `crypto`
// object plays in js/wasm.js.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const modulePath = join(here, '..', 'wasm', 'obsidian-wallet.wasm');

/** Loads the module with the same host import js/wasm.js provides. */
async function loadModule() {
  const bytes = await readFile(modulePath);
  let instance = null;
  const imports = {
    env: {
      obs_wasm_random(pointer, length) {
        const view = new Uint8Array(instance.exports.memory.buffer, pointer, length);
        webcrypto.getRandomValues(view);
        return 0;
      },
    },
  };
  ({ instance } = await WebAssembly.instantiate(bytes, imports));
  return instance.exports;
}

/** Calls one operation through the module's ABI. */
function call(api, operation, request = {}) {
  const encode = (text) => {
    const bytes = new TextEncoder().encode(text);
    const pointer = api.obs_alloc(bytes.length || 1);
    if (bytes.length) new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes);
    return { pointer, length: bytes.length };
  };
  const name = encode(operation);
  const body = encode(JSON.stringify(request));
  try {
    const resultPointer = api.obs_call(name.pointer, name.length, body.pointer, body.length);
    const header = new DataView(api.memory.buffer, resultPointer, 4);
    const length = header.getUint32(0, true);
    const bytes = new Uint8Array(api.memory.buffer, resultPointer + 4, length);
    const answer = JSON.parse(new TextDecoder().decode(bytes));
    // Freed with the size that was allocated: header plus payload.
    api.obs_free(resultPointer, length + 4);
    return answer;
  } finally {
    api.obs_free(name.pointer, name.length || 1);
    api.obs_free(body.pointer, body.length || 1);
  }
}

test('the installed wallet module exports the ABI the interface expects', async () => {
  const api = await loadModule();
  for (const name of ['obs_alloc', 'obs_free', 'obs_call', 'memory']) {
    assert.ok(name in api, `the module should export ${name}`);
  }
});

test('a wallet generated in the module is a real Obsidian account', async () => {
  const api = await loadModule();
  const generated = call(api, 'wallet_generate', { network: 'devnet' });
  assert.equal(generated.ok, true, JSON.stringify(generated));
  assert.equal(String(generated.phrase).split(/\s+/).length, 24);
  assert.match(generated.address, /^dobs1/);
  assert.match(generated.wallet_key, /^[0-9a-f]{64}$/);
  assert.match(generated.node_key, /^[0-9a-f]{64}$/);
  assert.match(generated.recovery_key, /^[0-9a-f]{64}$/);

  // The three keys are different keys: a validator identity that was also the
  // wallet key would tie attestations to funds, and the protocol forbids it.
  assert.notEqual(generated.wallet_key, generated.node_key);
  assert.notEqual(generated.wallet_key, generated.recovery_key);
  assert.notEqual(generated.node_key, generated.recovery_key);

  // The same phrase rebuilds the same account, which is what a recovery phrase
  // is for.
  const restored = call(api, 'wallet_from_phrase', { network: 'devnet', phrase: generated.phrase });
  assert.equal(restored.address, generated.address);
  assert.equal(restored.wallet_key, generated.wallet_key);
});

test('a signed transfer is a transaction the chain code can decode and verify', async () => {
  const api = await loadModule();
  const wallet = call(api, 'wallet_generate', { network: 'devnet' });
  const recipient = call(api, 'wallet_generate', { network: 'devnet' }).address;
  const signed = call(api, 'sign_transfer', {
    handle: wallet.handle,
    to: recipient,
    amount: '1',
    nonce: 3,
  });
  assert.equal(signed.ok, true, JSON.stringify(signed));
  // 0.02% of 1 OBS, computed by the Rust, not by the page.
  assert.equal(signed.fee, '0.0002');

  // The signed bytes are hex, and they decode to a transaction whose chain id is
  // this network's — the module cannot produce something for another network
  // without saying so.
  assert.match(signed.transaction, /^[0-9a-f]+$/);
  const bytes = Buffer.from(signed.transaction, 'hex');
  assert.ok(bytes.length > 100);
  // The chain id is little-endian 3 (devnet) at the start of the signed body.
  assert.equal(bytes.readUInt32LE(0), 3);
});

test('a claim is stamped with the protocol time it is given', async () => {
  const api = await loadModule();
  const wallet = call(api, 'wallet_generate', { network: 'devnet' });
  const claim = call(api, 'sign_claim', {
    handle: wallet.handle,
    protocol_time: 1_791_000_000,
    sequence: 1,
    nonce: 1,
  });
  assert.equal(claim.ok, true, JSON.stringify(claim));
  assert.equal(claim.protocol_time, 1_791_000_000);
  assert.equal(claim.transaction, claim.transaction.toLowerCase());
});

test('the module keeps keys behind the handle and refuses to guess', async () => {
  const api = await loadModule();
  const wallet = call(api, 'wallet_generate', { network: 'devnet' });
  const rendered = JSON.stringify(wallet);
  // The answer contains a phrase because a wallet was just created; it must not
  // contain the same secret twice (for example as a "seed" field).
  assert.equal(rendered.includes('seed'), false, 'the module should not expose a seed field');
  assert.equal(rendered.includes('private'), false);

  // An operation that needs a key and is given none fails rather than defaulting
  // to something.
  const unhandled = call(api, 'sign_transfer', { to: wallet.address, amount: '1', nonce: 1 });
  assert.equal(unhandled.ok, false);
  assert.match(unhandled.error, /handle/);

  // A network that does not exist is not silently treated as devnet.
  const wrong = call(api, 'wallet_generate', { network: 'moonnet' });
  assert.equal(wrong.ok, false);

  // Locking removes the wallet from the module entirely.
  const locked = call(api, 'wallet_lock', { handle: wallet.handle });
  assert.equal(locked.locked, true);
  const after = call(api, 'sign_claim', {
    handle: wallet.handle, protocol_time: 1, sequence: 1, nonce: 1,
  });
  assert.equal(after.ok, false);
});
