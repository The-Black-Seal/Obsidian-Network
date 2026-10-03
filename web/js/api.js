// The network's HTTP surfaces, as this interface is allowed to see them.
//
// Three services, three jobs, and the interface keeps them apart:
//
//   * the node       — the authority.  Blocks, transactions, supply, validators,
//                      and an account's own state *to the holder of its key*.
//   * the explorer   — a read-only index of the node.  Partial addresses, no
//                      balances, no way to write anything.
//   * the account    — registration, sign-in, invitations.  The six-step flow
//                      and the session that follows it.
//
// Every call goes to the same origin as the page.  A deployment can put the
// three behind different hosts, but the default — and the one the acceptance run
// uses — is one origin, which is what makes a cookie and an API-key header
// usable at all.
//
// Two rules this module enforces rather than documents:
//
//   1. It never sends a secret to the node.  A signature, yes; a key, never.
//   2. It never treats an HTTP 200 as success without reading `ok`.  Every
//      service in this workspace answers a refusal with `{ok: false, error:{...}}`,
//      and a client that only checks the status code will happily render a
//      refusal as data.

/** A refusal from any service, with the service's own error code. */
export class ApiError extends Error {
  constructor(message, { code = 'error', status = 0, url = '' } = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.url = url;
  }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const init = { method, headers: { Accept: 'application/json', ...headers } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch (cause) {
    throw new ApiError(`the service at ${path} could not be reached`, { code: 'unreachable', url: path });
  }
  const text = await response.text();
  let json = null;
  if (text) {
    try { json = JSON.parse(text); } catch (cause) { json = null; }
  }
  if (!response.ok) {
    const error = json && json.error ? json.error : {};
    throw new ApiError(
      error.message || `the service refused with status ${response.status}`,
      { code: error.code || 'refused', status: response.status, url: path },
    );
  }
  if (json && json.ok === false) {
    throw new ApiError(json.error || 'the request was refused', { code: 'refused', url: path });
  }
  return raw ? text : json;
}


/**
 * Where the node's API lives, as seen from this page.
 *
 * By default the page asks its own origin, under `/node`.  That is the
 * read-through `obs-app` serves: the node's public read paths, plus a signed
 * transaction submission, forwarded to the node the service indexes.  One origin
 * means no second host, no CORS preflight and nothing for a person to configure.
 *
 * A deployment that publishes the node directly — or serves this interface from
 * static hosting — can point the page somewhere else with a tag in the document
 * head:
 *
 *     <meta name="obsidian-node-api" content="https://node.example.com">
 *
 * This base is a *location*, never a permission: whatever it says, the node still
 * validates everything it is sent, and the page still cannot sign with a key it
 * does not hold.
 */
function node_base() {
  if (typeof document !== 'undefined' && typeof document.querySelector === 'function') {
    const meta = document.querySelector('meta[name="obsidian-node-api"]');
    const content = meta && typeof meta.getAttribute === 'function'
      ? meta.getAttribute('content')
      : null;
    if (content) return String(content).replace(/\/+$/, '');
  }
  return '/node';
}

/** The node's API base for this page. */
export const NODE_BASE = node_base();

/** The node: the chain itself. */
export const node = {
  status: () => request(`${NODE_BASE}/api/v1/status`),
  supply: () => request(`${NODE_BASE}/api/v1/supply`),
  mining: () => request(`${NODE_BASE}/api/v1/mining`),
  params: () => request(`${NODE_BASE}/api/v1/params`),
  blocks: (limit = 20, offset = 0) => request(`${NODE_BASE}/api/v1/blocks?limit=${limit}&offset=${offset}`),
  block: (selector) => request(`${NODE_BASE}/api/v1/blocks/${encodeURIComponent(selector)}`),
  transaction: (id) => request(`${NODE_BASE}/api/v1/transactions/${encodeURIComponent(id)}`),
  validators: () => request(`${NODE_BASE}/api/v1/validators`),
  mempool: () => request(`${NODE_BASE}/api/v1/mempool`),
  peers: () => request(`${NODE_BASE}/api/v1/peers`),
  events: (limit = 20) => request(`${NODE_BASE}/api/v1/events?limit=${limit}`),

  /** Submits already-signed bytes.  The node validates them; this cannot sign. */
  submit: (hex) => request(`${NODE_BASE}/api/v1/transactions`, { method: 'POST', body: { transaction: hex } }),

  /**
   * Reads an account's own state, proving ownership of the address.
   *
   * There is no other way to learn a balance from this interface, and that is
   * the point: the endpoint requires a signature over a challenge bound to the
   * chain and a fresh nonce, so it answers the account's holder and nobody else.
   * The explorer has no such endpoint at all.
   */
  accountProof: (address, nonce, signature) =>
    request(`${NODE_BASE}/api/v1/account/proof`, {
      method: 'POST',
      body: { address, nonce, signature },
    }),
};

/** The explorer index: what the public interface is allowed to show. */
export const explorer = {
  status: () => request('/v1/explorer/status'),
  blocks: (limit = 20, offset = 0) => request(`/v1/explorer/blocks?limit=${limit}&offset=${offset}`),
  block: (selector) => request(`/v1/explorer/blocks/${encodeURIComponent(selector)}`),
  transaction: (id) => request(`/v1/explorer/transactions/${encodeURIComponent(id)}`),
  address: (address) => request(`/v1/explorer/address/${encodeURIComponent(address)}`),
  validators: () => request('/v1/explorer/validators'),
  supply: () => request('/v1/explorer/supply'),
  mining: () => request('/v1/explorer/mining'),
  search: (query) => request(`/v1/explorer/search?q=${encodeURIComponent(query)}`),
  routes: () => request('/v1/routes'),
};

/** Accounts: registration, sign-in, invitations. */
export const accounts = {
  network: () => request('/v1/network'),
  begin: (gmail) => request('/v1/register/begin', { method: 'POST', body: { gmail } }),
  password: (token, password) =>
    request('/v1/register/password', { method: 'POST', body: { token, password } }),
  invite: (token, code) => request('/v1/register/invite', { method: 'POST', body: { token, code } }),
  recoveryCode: (token) => request('/v1/register/recovery-code', { method: 'POST', body: { token } }),
  enrolMfa: (token) => request('/v1/register/mfa', { method: 'POST', body: { token } }),
  confirmMfa: (token, code) =>
    request('/v1/register/mfa/confirm', { method: 'POST', body: { token, code } }),
  attachWallet: (token, keys) =>
    request('/v1/register/wallet', {
      method: 'POST',
      body: {
        token,
        wallet_key: keys.wallet_key,
        node_key: keys.node_key,
        recovery_key: keys.recovery_key,
      },
    }),
  signIn: (gmail, password, mfa_code) =>
    request('/v1/auth/sign-in', { method: 'POST', body: { gmail, password, mfa_code } }),
  signOut: (token) => request('/v1/auth/sign-out', { method: 'POST', headers: bearer(token) }),
  me: (token) => request('/v1/account', { headers: bearer(token) }),
  invites: (token) => request('/v1/invites', { headers: bearer(token) }),
  issueInvite: (token) => request('/v1/invites', { method: 'POST', body: {}, headers: bearer(token) }),
  recoveryVerify: (gmail, code) =>
    request('/v1/recovery/verify', { method: 'POST', body: { gmail, code } }),
  recoveryMfa: (token, code) =>
    request('/v1/recovery/mfa', { method: 'POST', body: { token, code } }),
};

/** The developer portal: API keys and their use. */
export const portal = {
  scopes: () => request('/v1/portal/scopes'),
  keys: (token) => request('/v1/portal/keys', { headers: bearer(token) }),
  create: (token, { label, scopes, requests_per_minute }) =>
    request('/v1/portal/keys', {
      method: 'POST',
      headers: bearer(token),
      body: { label, scopes, requests_per_minute },
    }),
  revoke: (token, id) => request(`/v1/portal/keys/${id}`, { method: 'DELETE', headers: bearer(token) }),
  rotate: (token, id) => request(`/v1/portal/keys/${id}/rotate`, { method: 'POST', body: {}, headers: bearer(token) }),
  usage: (token) => request('/v1/portal/usage', { headers: bearer(token) }),
  openapi: () => request('/v1/portal/openapi.json'),
};

function bearer(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** A short, human-readable form of a refusal, for the interface to render. */
export function describe(error) {
  if (error instanceof ApiError) {
    if (error.code === 'unreachable') {
      return 'The service did not answer. Nothing here is cached: this interface shows the chain or it shows nothing.';
    }
    return error.message;
  }
  return error && error.message ? error.message : String(error);
}
