// The shell: routing, the network badge, the protocol facts in the footer, and
// the two things every view needs — a way to say something happened, and a way
// to say something went wrong.

import { describe, node } from './api.js';
import { amount, element, moment } from './format.js';
import { refresh, start, state, subscribe } from './state.js';
import { replace } from './ui.js';

import * as developers from './views/developers.js';
import * as explorer from './views/explorer.js';
import * as mining from './views/mining.js';
import * as wallet from './views/wallet.js';

const routes = [
  { path: 'mining', title: 'Mining', view: mining },
  { path: 'wallet', title: 'Wallet', view: wallet },
  { path: 'explorer', title: 'Explorer', view: explorer },
  { path: 'developers', title: 'Developers', view: developers },
];

const main = document.getElementById('main');
const netBadge = document.getElementById('net-badge');
const netName = document.getElementById('net-name');
const offline = document.getElementById('offline');
const offlineDetail = document.getElementById('offline-detail');
const facts = document.getElementById('protocol-facts');
const toastBox = document.getElementById('toast');

let toastTimer = null;

/** Tells the user something happened.  `kind` is '', 'good' or 'bad'. */
export function say(title, detail = '', kind = '') {
  toastBox.className = `toast ${kind}`.trim();
  replace(toastBox, element('span', { className: 'title', text: title }),
    detail ? element('span', { text: detail }) : null);
  toastBox.hidden = false;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toastBox.hidden = true; }, kind === 'bad' ? 9000 : 5000);
}

/** Reports a failure in the same place, with the service's own words. */
export function failed(error, context = '') {
  const message = describe(error);
  console.error(error);
  say(context ? `${context} failed` : 'That did not work', message, 'bad');
}

/** The current route, from the hash: `#/explorer/blocks` -> ['explorer', 'blocks']. */
function route() {
  const raw = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  return raw.length ? raw : ['mining'];
}

async function renderRoute() {
  const [name, ...rest] = route();
  const match = routes.find((candidate) => candidate.path === name) || routes[0];
  document.title = `${match.title} · Obsidian Network`;
  for (const link of document.querySelectorAll('[data-nav]')) {
    link.toggleAttribute('aria-current', link.dataset.nav === match.path);
    if (link.dataset.nav === match.path) link.setAttribute('aria-current', 'page');
  }
  main.replaceChildren();
  try {
    await match.view.render(main, { segments: rest, navigate });
  } catch (error) {
    failed(error, `The ${match.title} view`);
    replace(main, element('h1', { text: match.title }),
      element('p', { className: 'dim', text: describe(error) }));
  }
  main.focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
}

/** Navigates by hash, so every view is linkable and the back button works. */
export function navigate(path) {
  const next = `#/${path.replace(/^#?\/?/, '')}`;
  if (location.hash === next) renderRoute();
  else location.hash = next;
}

function paintShell() {
  if (state.reachable) {
    netBadge.className = 'net live';
    const name = state.status.network;
    netName.textContent = `${name} · chain ${state.status.chain_id}`;
    netBadge.title = `Connected to a ${name} node: height ${state.status.height}, protocol time ${state.status.protocol_time}`;
    offline.hidden = true;
  } else {
    netBadge.className = 'net down';
    netName.textContent = 'no node';
    offline.hidden = false;
    if (state.error) offlineDetail.textContent = ` ${state.error}`;
  }

  // The footer is the protocol's own arithmetic, read from the chain rather than
  // written here: the interface has no constants of its own to drift.
  if (state.status && state.supply && state.mining) {
    const parts = [
      `${amount(state.supply.max_supply)} maximum supply`,
      `${amount(state.supply.issued_supply)} issued`,
      `${amount(state.mining.reward_per_claim)} per claim every ${Math.round(state.mining.interval_secs / 3600)} h`,
      `${state.mining.active_miners} active ${state.mining.active_miners === 1 ? 'miner' : 'miners'}`,
      `height ${state.status.height}`,
      `protocol time ${moment(state.status.protocol_time)}`,
    ];
    facts.textContent = parts.join(' · ');
  } else {
    facts.textContent = 'The protocol\'s constants could not be read from the chain.';
  }
}

subscribe(paintShell);
window.addEventListener('hashchange', renderRoute);
window.addEventListener('DOMContentLoaded', () => {
  renderRoute();
  start(5000);
});
// The node's clock is the chain's; a tab that has been asleep should re-read
// rather than show a stale head.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refresh();
});

export { node, state };
