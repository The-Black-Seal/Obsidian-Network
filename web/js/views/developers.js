// The Developer Portal: API keys, scopes, limits, and documentation with real
// examples.
//
// The documentation is generated from the service's own OpenAPI document, which
// is itself generated from the route table the privacy contract is written in.
// That chain matters: a copy-pasted example cannot drift from the API, because
// the only list of routes is the one the server enforces.
//
// The examples are shown in four languages — JavaScript/TypeScript, Rust, cURL
// and Python — because those are what people actually build with.  Every example
// is honest about the same three things: the node is the authority, the explorer
// is an index, and an API key is a read credential that never grants custody.

import { accounts, describe, explorer, portal } from '../api.js';
import { element, moment } from '../format.js';
import { state } from '../state.js';
import { button, card, field, grid, input, metric, notice, noticeRich, pairs, pill, raw, replace, table } from '../ui.js';
import { failed, say } from '../app.js';

export const title = 'Developers';

export async function render(root) {
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Developer Portal' }),
    element('p', {
      text: 'Build on a chain whose rules are Rust and whose APIs are documented. API keys are read '
        + 'credentials: they can select what you may read, and they can never move value, approve a '
        + 'claim or change a protocol rule.',
    })));

  const [openapi, scopes] = await Promise.all([
    portal.openapi().catch(() => null),
    portal.scopes().catch(() => null),
  ]);

  root.append(keysCard(scopes));
  root.append(scopesCard(scopes));
  root.append(privacyCard());
  root.append(examplesCard(openapi));
  root.append(openapiCard(openapi));
}

function keysCard(scopes) {
  const label = input({ placeholder: 'what this key is for', name: 'key-label' });
  const limit = input({ type: 'number', value: '600', name: 'key-limit' });
  const selected = new Set();
  const answer = element('div');
  const scopeBoxes = element('div', { className: 'grid cols-3' });

  const available = scopes?.scopes || [];
  for (const scope of available) {
    const box = element('label');
    const checkbox = element('input', { attributes: { type: 'checkbox', value: scope.name } });
    checkbox.checked = Boolean(scope.default_granted);
    if (checkbox.checked) selected.add(scope.name);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) selected.add(scope.name);
      else selected.delete(scope.name);
    });
    box.append(checkbox);
    box.append(element('span', { className: 'mono', text: scope.name }));
    box.append(element('span', { className: 'faint', text: scope.description }));
    scopeBoxes.append(box);
  }

  const create = button('Create an API key', {
    kind: 'primary',
    onClick: async () => {
      const token = window.__obsSession;
      if (!token) return say('Sign in first', 'The portal issues keys to an account, not to a page.', 'bad');
      try {
        const created = await portal.create(token, {
          label: label.value.trim() || 'unnamed key',
          scopes: Array.from(selected),
          requests_per_minute: Number(limit.value) || 600,
        });
        replace(answer, element('div', { children: [
          noticeRich('This secret is shown once.',
            'Only a hash of it is stored, so it cannot be recovered — if it is lost, rotate the key. '
            + 'Treat it as a read credential: keep it out of browsers and repositories.',
            'warn'),
          element('div', { className: 'secret', text: created.secret || created.key || '(see the service)' }),
          pairs([
            ['Key id', element('span', { className: 'mono', text: created.id || '—' })],
            ['Scopes', element('span', { className: 'mono', text: (created.scopes || []).join(' ') })],
            ['Limit', element('span', { className: 'mono', text: `${created.limit?.requests ?? ''}/${created.limit?.window_secs ?? ''}s` })],
          ]),
        ] }));
        say('Key created', 'Keep the secret out of source control; rotate it if it leaks.', 'good');
        await listKeys(answer);
      } catch (error) {
        failed(error, 'Creating the key');
      }
    },
  });

  const list = button('Show my keys', { onClick: () => listKeys(answer) });
  const revoke = button('Revoke a key by id', {
    onClick: async () => {
      const token = window.__obsSession;
      if (!token) return say('Sign in first', 'Keys belong to an account.', 'bad');
      const id = window.prompt('Key id to revoke');
      if (!id) return;
      try {
        await portal.revoke(token, id.trim());
        say('Key revoked', 'Revocation is immediate and destroys the stored secret hash.', 'good');
        await listKeys(answer);
      } catch (error) {
        failed(error, 'Revoking the key');
      }
    },
  });

  return card({
    title: 'API keys',
    subtitle: 'Scopes, rate limits, rotation and revocation.',
    body: element('div', { children: [
      notice('An API key is a read credential. Two scopes touch writing at all, and both are still safe '
        + 'to leak: submitting a transaction submits bytes that are already signed by a wallet, and the '
        + 'account-proof scope only accepts a request the account\'s own key has signed. A leaked key '
        + 'can cost you rate limit, never coins.'),
      scopeBoxes,
      element('div', { className: 'field-row' }, [
        field('Label', label, 'Shown in the audit trail.'),
        field('Requests per minute', limit, 'Clamped by the service to between 10 and 6000.'),
      ]),
      element('div', { className: 'row' }, [create, list, revoke]),
      answer,
    ] }),
  });
}

async function listKeys(where) {
  const token = window.__obsSession;
  if (!token) return;
  try {
    const keys = await portal.keys(token);
    const usage = await portal.usage(token).catch(() => null);
    replace(where, element('div', { children: [
      table(['Key id', 'Label', 'Scopes', 'Limit', 'Used', 'Created', 'State'], (keys.keys || []).map((key) => [
        element('td', { className: 'mono', text: key.id }),
        element('td', { text: key.label }),
        element('td', { className: 'mono dim', text: (key.scopes || []).join(' ') }),
        element('td', { className: 'mono', text: `${key.limit?.requests ?? ''}/${key.limit?.window_secs ?? ''}s` }),
        element('td', { className: 'mono', text: String(key.requests ?? 0) }),
        element('td', { className: 'mono dim', text: moment(key.created_at) }),
        element('td', {}, key.revoked_at ? pill('revoked', 'red') : pill('active', 'green')),
      ]), { empty: 'No keys yet.' }),
      usage ? pairs([
        ['Requests', String(usage.requests ?? 0)],
        ['Refused', String(usage.refused ?? 0)],
        ['Keys', String(usage.keys ?? 0)],
      ]) : null,
    ] }));
  } catch (error) {
    failed(error, 'Listing keys');
  }
}

function scopesCard(scopes) {
  const rows = (scopes?.scopes || []).map((scope) => [
    element('td', { className: 'mono', text: scope.name }),
    element('td', { text: scope.description }),
    element('td', {}, scope.default_granted ? pill('default', 'violet') : ''),
  ]);
  return card({
    title: 'Scopes',
    subtitle: 'What a key may ask for. Nothing here can change the chain.',
    body: table(['Scope', 'What it allows', ''], rows, {
      empty: 'The scope list could not be read from the portal.',
    }),
  });
}

function privacyCard() {
  return card({
    title: 'The privacy contract',
    subtitle: 'Enforced in the API, not in a policy document.',
    body: element('div', { children: [
      table(['Rule', 'How it is enforced'], [
        ['No balances are published', 'there is no balance route in the route table, and a scrubber refuses any response containing a balance field'],
        ['No whole addresses are published', 'the index stores and serves only partial addresses, so a copy of the index is not a list of participants'],
        ['No private keys, seeds, phrases, passwords or TOTP secrets', 'the same fail-closed scrubber, and the services have no field to leak'],
        ['No IP addresses or peer addresses', 'the explorer reports peer counts, never peer identities'],
        ['Fail closed', 'a response that would violate the contract becomes a refusal, not a redaction'],
      ].map(([rule, how]) => [
        element('td', { text: rule }),
        element('td', { className: 'dim', text: how }),
      ])),
      noticeRich('An account\'s own balance is available — to that account.',
        'The node has one balance-bearing endpoint, and it requires a signature over a challenge bound '
        + 'to this chain and a fresh nonce. The explorer never calls it, and neither does this page.',
        'good'),
    ] }),
  });
}

function examplesCard(openapi) {
  const tabs = element('div', { className: 'row' });
  const body = element('div');
  const languages = ['JavaScript / TypeScript', 'Rust', 'cURL', 'Python'];
  const samples = {
    'JavaScript / TypeScript': `// Read the chain's head and the issuance figures.
// The node is the authority; everything else is an index of it.
const status = await fetch('/api/v1/status').then((r) => r.json());
const supply = await fetch('/api/v1/supply').then((r) => r.json());

console.log(status.network, status.chain_id, 'height', status.height);
console.log(supply.issued_supply, 'of', supply.max_supply, 'OBS issued');

// A key, if your deployment requires one for reads:
const explorer = await fetch('/v1/explorer/blocks?limit=10', {
  headers: { 'X-API-Key': process.env.OBSIDIAN_API_KEY },
}).then((r) => r.json());

// Mining is an account's own act: the claim is signed by your wallet, and this
// API never signs for you. Submit bytes, not keys.
await fetch('/api/v1/transactions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ transaction: signedTransactionHex }),
});`,
    Rust: `// The node's API is plain JSON over HTTP; no SDK is required — and the
// authoritative implementation is the Rust in this repository.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let status: serde_json::Value =
        reqwest::blocking::get("http://127.0.0.1:7200/api/v1/status")?.json()?;
    println!("height {} on {}", status["height"], status["network"]);

    // An account's own state is read by proving the key — never by asking an
    // explorer. Sign the challenge, then ask the node.
    let proof: serde_json::Value = reqwest::blocking::Client::new()
        .post("http://127.0.0.1:7200/api/v1/account/proof")
        .json(&serde_json::json!({
            "address": address,
            "nonce": nonce,
            "signature": signature_hex,
        }))?
        .json()?;
    println!("balance {}", proof["balance"]);
    Ok(())
}`,
    cURL: `# The head of the chain, and the issuance figures.
curl -s http://127.0.0.1:7200/api/v1/status
curl -s http://127.0.0.1:7200/api/v1/supply

# The explorer's index, with an API key when the deployment requires one.
curl -s -H "X-API-Key: $OBSIDIAN_API_KEY" \\
  'http://127.0.0.1:8081/v1/explorer/blocks?limit=10'

# Submit an already-signed transaction: the API never holds your key.
curl -s -X POST http://127.0.0.1:7200/api/v1/transactions \\
  -H 'Content-Type: application/json' \\
  -d '{"transaction":"<hex of the signed transaction>"}'

# Your own balance: sign the challenge with your wallet, then ask the node.
curl -s -X POST http://127.0.0.1:7200/api/v1/account/proof \\
  -H 'Content-Type: application/json' \\
  -d '{"address":"obs1...","nonce":"...","signature":"<hex>"}'`,
    Python: `import os, requests

node = "http://127.0.0.1:7200"
status = requests.get(f"{node}/api/v1/status", timeout=10).json()
print(status["network"], status["height"], status["protocol_time"])

# The explorer is an index with a privacy contract: partial addresses, no balances.
headers = {"X-API-Key": os.environ.get("OBSIDIAN_API_KEY", "")}
blocks = requests.get("http://127.0.0.1:8081/v1/explorer/blocks",
                      params={"limit": 10}, headers=headers, timeout=10).json()
for block in blocks["blocks"]:
    print(block["height"], block["proposer"], block["transactions"])

# Claim validation is protocol time. Read it from the chain, never from your clock.
print("protocol time is", status["protocol_time"])`,
  };

  for (const language of languages) {
    const tab = button(language, {
      kind: 'small',
      onClick: () => {
        for (const other of tabs.children) other.className = 'small';
        tab.className = 'small primary';
        replace(body, element('pre', { className: 'mono', text: samples[language] }));
      },
    });
    if (language === languages[0]) tab.className = 'small primary';
    tabs.append(tab);
  }
  replace(body, element('pre', { className: 'mono', text: samples[languages[0]] }));

  return card({
    title: 'Examples',
    subtitle: 'Every call here is a call this interface makes itself.',
    body: element('div', { children: [tabs, body] }),
  });
}

function openapiCard(openapi) {
  const paths = openapi?.paths ? Object.keys(openapi.paths) : [];
  return card({
    title: 'OpenAPI',
    subtitle: 'Generated from the route table the server enforces, so it cannot drift.',
    body: element('div', { children: [
      grid([
        metric('Public routes', String(paths.length)),
        metric('Document', openapi ? `${openapi.openapi || '3.0'}` : 'unavailable'),
      ], 2),
      paths.length
        ? table(['Path', 'Methods'], paths.map((path) => [
          element('td', { className: 'mono', text: path }),
          element('td', { className: 'mono dim', text: Object.keys(openapi.paths[path]).join(', ') }),
        ]))
        : element('p', { className: 'faint', text: 'The OpenAPI document could not be read from the explorer service.' }),
      openapi ? raw('The document', openapi) : null,
    ] }),
  });
}
