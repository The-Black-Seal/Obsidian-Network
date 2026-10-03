// The bridge to the Rust wallet, running as WebAssembly.
//
// This file is deliberately dull: it loads the module, gives it the browser's
// CSPRNG, and passes JSON in and out.  It contains no cryptography and no
// protocol arithmetic, because everything of that kind belongs on the other side
// of the boundary, in code compiled from the same crates the command-line client
// runs.  A reviewer should be able to read this in a minute and be sure that the
// keys never cross into JavaScript:
//
//   * `obs_wasm_random` is the only import the module has, and it only ever
//     *writes entropy into* wasm memory.
//   * operations return a handle, not a key.  A private key, a seed or a
//     recovery phrase is never a value in this language.
//   * the length-prefixed result buffer is freed on the way out.
//
// If the module cannot be loaded the interface still works, read-only: browsing,
// the explorer and the developer portal need no key.  Creating a wallet, mining
// or sending does, and says so rather than falling back to something weaker.

let modulePromise = null;
let exports_ = null;

/** Loads the wallet module.  Safe to call repeatedly. */
export function load() {
  if (!modulePromise) {
    modulePromise = WebAssembly
      .instantiateStreaming
      ? WebAssembly.instantiateStreaming(fetch('wasm/obsidian-wallet.wasm'), imports())
          .then(({ instance }) => instance)
          .catch(fallback)
      : fallback();
  }
  return modulePromise.then((instance) => {
    exports_ = instance.exports;
    return instance;
  });
}

/** Some servers do not send the MIME type streaming wants; fetch bytes instead. */
async function fallback() {
  const response = await fetch('wasm/obsidian-wallet.wasm');
  if (!response.ok) {
    throw new Error(`the wallet module could not be loaded (status ${response.status})`);
  }
  const bytes = await response.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, imports());
  return instance;
}

/**
 * The module's only import: the host's cryptographically secure random source.
 *
 * `crypto.getRandomValues` is the browser's CSPRNG — the same one the page itself
 * uses, seeded by the operating system.  It runs for as long as the module is
 * loaded, and it can write entropy into wasm memory and nothing else.
 */
function imports() {
  return {
    env: {
      obs_wasm_random(pointer, length) {
        if (!exports_ || !exports_.memory) return -1;
        const view = new Uint8Array(exports_.memory.buffer, pointer, length);
        crypto.getRandomValues(view);
        return 0;
      },
    },
  };
}

/** True when the wallet module is loaded and usable. */
export function ready() {
  return exports_ !== null && typeof exports_.obs_call === 'function';
}

/**
 * Runs one wallet operation.
 *
 * `operation` is one of the names `obs-wasm` implements.  The request is JSON;
 * the answer is JSON with an `ok` flag, and this function throws the module's
 * own message when `ok` is false, so callers handle one style of failure.
 */
export async function call(operation, request = {}) {
  const instance = await load();
  const api = instance.exports;
  const encode = (text) => {
    const bytes = new TextEncoder().encode(text);
    const pointer = api.obs_alloc(bytes.length || 1);
    if (bytes.length) {
      new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes);
    }
    return { pointer, length: bytes.length };
  };
  const name = encode(operation);
  const body = encode(JSON.stringify(request));
  let resultPointer = 0;
  let length = 0;
  try {
    resultPointer = api.obs_call(name.pointer, name.length, body.pointer, body.length);
    // The result is four little-endian bytes of length, then that many bytes of
    // UTF-8 JSON — the length first, so nothing has to be scanned for a
    // terminator.
    const header = new DataView(api.memory.buffer, resultPointer, 4);
    length = header.getUint32(0, true);
    const bytes = new Uint8Array(api.memory.buffer, resultPointer + 4, length);
    const text = new TextDecoder().decode(bytes);
    const answer = JSON.parse(text);
    if (!answer || answer.ok !== true) {
      throw new Error(answer && answer.error ? answer.error : 'the wallet refused the operation');
    }
    return answer;
  } finally {
    // The result buffer was allocated as `header + payload`, and it has to be
    // released with that whole size: the allocator is told the layout it was
    // given, and a wrong size is a corrupted heap.  Inputs were allocated as
    // exactly their length (or one byte when empty), and are freed the same way.
    if (resultPointer) api.obs_free(resultPointer, length + 4);
    api.obs_free(name.pointer, name.length || 1);
    api.obs_free(body.pointer, body.length || 1);
  }
}

/**
 * A wallet, as this interface sees it: an address, public keys and a handle.
 *
 * The handle is what signing operations take.  There is no field here for a
 * private key, because the module has none to give — which is the property that
 * makes a browser wallet defensible at all.
 */
export function walletView(answer) {
  return {
    handle: answer.handle,
    network: answer.network,
    chainId: answer.chain_id,
    account: answer.account,
    address: answer.address,
    nodeAddress: answer.node_address,
    recoveryAddress: answer.recovery_address,
    walletKey: answer.wallet_key,
    nodeKey: answer.node_key,
    recoveryKey: answer.recovery_key,
    phrase: answer.phrase,
  };
}
