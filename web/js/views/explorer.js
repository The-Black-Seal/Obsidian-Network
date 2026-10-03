// The Explorer: what the chain says, and what it deliberately does not.
//
// This view reads the explorer index, not the node's API directly, so that what
// a visitor sees here is exactly what a developer building on the API sees.  It
// has one rule it never breaks: it does not publish balances and does not
// publish whole addresses.  There is no balance endpoint to call — the index
// does not have one — and every address it prints is the partial form the index
// stores.  A person's own balance belongs to that person, and the wallet asks
// for it by proving ownership.

import { describe, explorer, node } from '../api.js';
import {
  amount, amountWhole, basisPoints, element, grains, moment, partialAddress, shortHash, until,
} from '../format.js';
import { state } from '../state.js';
import { button, card, grid, input, metric, pairs, pill, raw, replace, table } from '../ui.js';
import { failed, say } from '../app.js';

export const title = 'Explorer';

export async function render(root, { segments, navigate }) {
  const [section, selector] = segments;
  root.append(element('section', { className: 'view' }));

  if (section === 'block' && selector) return renderBlock(root, selector, navigate);
  if (section === 'transaction' && selector) return renderTransaction(root, selector, navigate);
  if (section === 'address' && selector) return renderAddress(root, selector, navigate);
  if (section === 'validators') return renderValidators(root, navigate);

  await renderHome(root, navigate);
}

async function renderHome(root, navigate) {
  const [status, supply, mining, blocks, validators] = await Promise.all([
    explorer.status(),
    explorer.supply(),
    explorer.mining(),
    explorer.blocks(12),
    explorer.validators().catch(() => null),
  ]);

  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Explorer' }),
    element('p', {
      text: 'Blocks, transactions, validator participation and issuance — read from a read-only '
        + 'index of a node. Addresses appear in partial form and balances never appear at all: '
        + 'the explorer publishes activity, not holdings.',
    })));

  root.append(grid([
    metric('Height', String(status.height ?? state.status?.height ?? '—'), { title: 'Blocks since genesis' }),
    metric('Issued supply', amountWhole(supply.issued_supply), { unit: `of ${amount(supply.max_supply)}` }),
    metric('Remaining', amountWhole(supply.remaining), { unit: 'still to be issued' }),
    metric('Active miners', String(mining.active_miners), { unit: 'claimed within 30 days' }),
    metric('Reward per claim', amount(mining.reward_per_claim, { unit: false }), { unit: 'OBS every 4 hours' }),
    metric('Genesis', supply.genesis_issued ? 'issued' : 'not yet claimed', {
      unit: `treasury allocation ${amount(supply.genesis_allocation)}`,
    }),
  ], 3));

  // The index can lag the node.  Saying so is the difference between an explorer
  // and a story.
  const lag = state.indexStatus;
  if (lag) {
    const behind = Number(status.height) - Number(lag.indexed_height);
    root.append(card({
      title: 'The index',
      subtitle: 'The explorer follows a node; it is not the node.',
      body: element('div', { className: 'grid cols-3' }, [
        metric('Node height', String(status.height)),
        metric('Indexed height', String(lag.indexed_height)),
        metric('Behind', behind > 0 ? `${behind} blocks` : 'current'),
      ]),
    }));
  }

  root.append(card({
    title: 'Search',
    body: buildSearch(navigate),
  }));

  const rows = (blocks.blocks || []).map((block) => [
    linkCell(`#/explorer/block/${block.height}`, String(block.height), 'mono'),
    element('td', { className: 'mono', text: shortHash(block.hash) }),
    element('td', { className: 'mono', text: partialAddress(block.proposer) }),
    element('td', { className: 'mono', text: String(block.transactions) }),
    element('td', { className: 'mono dim', text: moment(block.timestamp) }),
    element('td', { className: 'right' }, pill(block.finalized ? 'finalized' : 'provisional',
      block.finalized ? 'green' : 'amber')),
  ]);
  root.append(card({
    title: 'Recent blocks',
    subtitle: 'Proposers appear as partial addresses.',
    body: table(['Height', 'Hash', 'Proposer', 'Transactions', 'Protocol time', ''], rows,
      { empty: 'No blocks yet: this network has not produced its first block.' }),
  }));

  if (validators && validators.validators) {
    root.append(card({
      title: 'Validators',
      subtitle: 'Uptime is evidence, never self-reported: it is computed from attestations in blocks.',
      actions: [button('All validators', { kind: 'small', onClick: () => navigate('explorer/validators') })],
      body: table(
        ['Node key', 'Owner', 'Bond', 'Uptime', 'Attestations', 'Blocks proposed'],
        validators.validators.slice(0, 5).map((validator) => [
          element('td', { className: 'mono', text: shortHash(validator.node_key, { head: 10, tail: 6 }) }),
          element('td', { className: 'mono', text: partialAddress(validator.owner) }),
          element('td', { className: 'mono', text: amount(validator.bond, { unit: false }) }),
          element('td', { className: 'mono', text: basisPoints(validator.uptime_bp) }),
          element('td', { className: 'mono', text: String(validator.attestations) }),
          element('td', { className: 'mono', text: String(validator.blocks_proposed) }),
        ]),
        { empty: 'No validators are registered yet.' },
      ),
    }));
  }

  root.append(raw('The index\'s raw answer for this page', { status, supply, mining, blocks }));
}

function buildSearch(navigate) {
  const query = input({ placeholder: 'height, block hash, transaction id or address', name: 'q' });
  const form = element('div', { className: 'search-row' });
  const run = async () => {
    const value = query.value.trim();
    if (!value) return;
    try {
      const answer = await explorer.search(value);
      const hit = answer.result || answer;
      const kind = hit.kind || 'nothing';
      if (kind === 'block') navigate(`explorer/block/${hit.height ?? hit.hash}`);
      else if (kind === 'transaction') navigate(`explorer/transaction/${hit.id}`);
      else if (kind === 'address') navigate(`explorer/address/${hit.address}`);
      else say('Nothing matched that', 'The search takes a height, a block hash, a transaction id or an address.');
    } catch (error) {
      failed(error, 'Search');
    }
  };
  const go = button('Search', { kind: 'primary', onClick: run });
  query.addEventListener('keydown', (event) => { if (event.key === 'Enter') run(); });
  form.append(query, go);
  const help = element('p', { className: 'hint', text: 'A height searches blocks; a 64-character hex string searches hashes and transaction ids; an obs1… address searches activity.' });
  return element('div', { children: [form, help] });
}

async function renderBlock(root, selector, navigate) {
  const block = await explorer.block(selector).catch(async (error) => {
    // A block the index has not caught up with is still readable from the node,
    // which is the authority for it.
    if (error && error.status === 404) return { fromNode: await node.block(selector) };
    throw error;
  });
  const data = block.fromNode || block;
  root.append(element('div', { className: 'hero' },
    element('h1', { text: `Block ${data.height ?? selector}` }),
    element('p', { className: 'mono dim', text: data.hash || '' })));

  root.append(grid([
    metric('Height', String(data.height)),
    metric('Protocol time', String(data.timestamp), { unit: moment(data.timestamp) }),
    metric('Transactions', String(data.transactions ?? (data.transaction_ids || []).length)),
    metric('Attestations', String(data.attestations ?? '—')),
    metric('PoT weight', String(data.weight_atoms ?? '—'), { unit: 'atoms, accumulated' }),
    metric('PoT difficulty', String(data.difficulty_bp ?? '—'), { unit: 'basis points' }),
  ], 3));

  root.append(card({
    title: 'Header',
    body: pairs([
      ['Proposer', element('span', { className: 'mono', text: partialAddress(data.proposer) })],
      ['Parent', element('span', { className: 'mono', text: data.parent || '—' })],
      ['State root', element('span', { className: 'mono', text: data.state_root || '—' })],
      ['Transaction root', element('span', { className: 'mono', text: data.tx_root || '—' })],
      ['Slot', element('span', { className: 'mono', text: String(data.slot ?? '—') })],
      ['Finalized', data.finalized ? pill('finalized', 'green') : pill('provisional', 'amber')],
    ]),
  }));

  const ids = data.transaction_ids || [];
  if (ids.length) {
    root.append(card({
      title: 'Transactions',
      body: table(['Transaction id'], ids.map((id) => [
        linkCell(`#/explorer/transaction/${id}`, id, 'mono'),
      ])),
    }));
  }
  root.append(raw('Raw block', data));
}

async function renderTransaction(root, id, navigate) {
  const transaction = await explorer.transaction(id);
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Transaction' }),
    element('p', { className: 'mono dim', text: transaction.id || id })));
  root.append(grid([
    metric('Kind', String(transaction.kind ?? '—')),
    metric('Status', String(transaction.status ?? '—')),
    metric('Block', transaction.height ? String(transaction.height) : 'pooled'),
    metric('Fee', transaction.fee ? amount(transaction.fee, { unit: false }) : '—', { unit: 'OBS' }),
    metric('Size', String(transaction.size_bytes ?? '—'), { unit: 'bytes' }),
  ], 3));
  root.append(card({
    title: 'Sender',
    subtitle: 'Partial, as everywhere in the explorer.',
    body: element('p', { className: 'mono', text: partialAddress(transaction.sender) }),
  }));
  root.append(raw('Raw transaction', transaction));
}

async function renderAddress(root, address, navigate) {
  const activity = await explorer.address(address);
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Address activity' }),
    element('p', { className: 'mono dim', text: activity.address || partialAddress(address) })));
  root.append(element('p', {
    className: 'notice',
    text: activity.note
      || 'The explorer publishes activity, not holdings. There is no balance here, by design: an '
        + 'account reads its own balance by proving ownership of its key.',
  }));
  root.append(grid([
    metric('Claims', String(activity.claims ?? 0), { unit: 'accepted mining claims' }),
    metric('Blocks proposed', String(activity.blocks_proposed ?? 0)),
    metric('First seen', activity.first_seen ? moment(activity.first_seen) : '—'),
    metric('Last seen', activity.last_seen ? moment(activity.last_seen) : '—'),
  ], 4));
  const heights = activity.recent_heights || [];
  if (heights.length) {
    root.append(card({
      title: 'Recent activity',
      body: table(['Block'], heights.map((height) => [
        linkCell(`#/explorer/block/${height}`, String(height), 'mono'),
      ])),
    }));
  }
  root.append(raw('Raw activity', activity));
}

async function renderValidators(root, navigate) {
  const validators = await explorer.validators();
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Validators' }),
    element('p', {
      text: 'A validator bonds 50 OBS and attests to blocks with a node identity that is not its '
        + 'wallet key. Uptime and score are computed from those attestations — nobody reports '
        + 'their own uptime.',
    })));
  root.append(grid([
    metric('Active', String(validators.active ?? 0)),
    metric('Quorum', String(validators.quorum ?? '—'), { unit: 'attestations per block' }),
  ], 2));
  const rows = (validators.validators || []).map((validator) => [
    element('td', { className: 'mono', text: shortHash(validator.node_key, { head: 12, tail: 8 }) }),
    element('td', { className: 'mono', text: partialAddress(validator.owner) }),
    element('td', { className: 'mono', text: amount(validator.bond, { unit: false }) }),
    element('td', { className: 'mono', text: basisPoints(validator.uptime_bp) }),
    element('td', { className: 'mono', text: String(validator.attestations) }),
    element('td', { className: 'mono', text: String(validator.blocks_proposed) }),
    element('td', { className: 'mono', text: String(validator.missed_slots) }),
    element('td', {}, pill(validator.active ? 'active' : 'inactive', validator.active ? 'green' : 'amber')),
  ]);
  root.append(card({
    title: 'Registered validators',
    subtitle: 'Bond, uptime, attestations, participation.',
    body: table(['Node key', 'Owner', 'Bond', 'Uptime', 'Attestations', 'Proposed', 'Missed', ''],
      rows, { empty: 'No validators are registered yet.' }),
  }));
  root.append(raw('Raw validator set', validators));
}

/** A table cell holding a link. */
function linkCell(href, text, className = '') {
  const cell = element('td', { className });
  const anchor = element('a', { text, attributes: { href } });
  cell.append(anchor);
  return cell;
}
