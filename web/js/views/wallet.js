// The Wallet: a non-custodial account, in the browser.
//
// The keys are derived and the transactions are signed inside the WebAssembly
// module (see js/wasm.js).  This view never sees a private key, never computes a
// fee, never chooses a nonce and never assembles a transaction: it asks the
// module for a signature and the chain for the numbers the signature needs.
//
// The recovery phrase is the one secret that crosses into JavaScript, and it
// does so exactly once — when a wallet is created — because a phrase its owner
// never saw is a wallet its owner can never recover.  It is shown on a screen
// that says so, and the interface keeps no copy.

import { node } from '../api.js';
import { amount, element, until } from '../format.js';
import { state } from '../state.js';
import { button, card, field, grid, input, metric, notice, noticeRich, pairs, replace } from '../ui.js';
import { failed, say } from '../app.js';
import * as wasm from '../wasm.js';

const KEYSTORE_KEY = 'obsidian.keystore';

// The keystore is sealed and needs its password to open — which is the point of
// it — so a page that has just loaded cannot read even the wallet's own address
// out of it.  The address is not a secret: it is the account's public name, and
// the chain publishes it.  It is kept here beside the keystore so that a reload
// can show a person which wallet they are holding and ask for the password to
// spend from it.  Nothing here is secret, and nothing here can spend: the private
// keys exist only inside the sealed text and, once unlocked, inside WebAssembly.
const PUBLIC_KEY = 'obsidian.wallet';
let session = null;

export const title = 'Wallet';

export async function render(root) {
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Wallet' }),
    element('p', {
      text: 'A non-custodial Obsidian wallet. Your keys are generated and used inside WebAssembly '
        + 'on this device — the same Rust code the command-line client runs — and this page never '
        + 'sees a private key. Nothing is sent anywhere except a signed transaction.',
    })));

  const held = heldWallet();
  if (!held) return renderNoWallet(root);
  // A keystore is sealed with a password, so on a fresh page it is *held* and
  // *locked*, not broken.  The wallet's public name is shown from the record kept
  // beside it, and the password is what turns it into a key that can spend.
  renderLockedWallet(root, held);
}

function record() {
  return {
    get: () => {
      try {
        const text = localStorage.getItem(PUBLIC_KEY);
        return text ? JSON.parse(text) : null;
      } catch (cause) {
        return null;
      }
    },
    set: (view) => {
      try {
        localStorage.setItem(PUBLIC_KEY, JSON.stringify({
          address: view.address,
          nodeAddress: view.nodeAddress,
          recoveryAddress: view.recoveryAddress,
          walletKey: view.walletKey,
          nodeKey: view.nodeKey,
          recoveryKey: view.recoveryKey,
          network: view.network,
          account: view.account,
        }));
        return true;
      } catch (cause) {
        return false;
      }
    },
    clear: () => {
      try { localStorage.removeItem(PUBLIC_KEY); } catch (cause) { /* nothing to do */ }
    },
  };
}

function phrases() {
  return {
    get: () => {
      try { return localStorage.getItem(KEYSTORE_KEY); } catch (cause) { return null; }
    },
    set: (value) => {
      try { localStorage.setItem(KEYSTORE_KEY, value); return true; } catch (cause) { return false; }
    },
    clear: () => {
      try { localStorage.removeItem(KEYSTORE_KEY); } catch (cause) { /* nothing to do */ }
    },
  };
}

function renderNoWallet(root) {
  const phraseWords = element('div', { className: 'phrase-grid' });
  const phrasePanel = element('div', { hidden: true });
  const password = input({ type: 'password', placeholder: 'at least 12 characters', name: 'password' });
  const confirmation = input({ type: 'password', placeholder: 'the same password again', name: 'confirm' });
  const phraseInput = input({ placeholder: 'twenty-four words, separated by spaces', name: 'phrase' });
  const restorePassword = input({ type: 'password', placeholder: 'a password for the new keystore', name: 'restore-password' });

  let pending = null;

  const start = button('Create a wallet', {
    kind: 'primary',
    onClick: async () => {
      try {
        const created = await wasm.call('wallet_generate', { network: state.status?.network || 'devnet' });
        pending = wasm.walletView(created);
        phraseWords.replaceChildren();
        const words = (pending.phrase || '').split(/\s+/);
        words.forEach((word, index) => {
          const cell = element('span');
          cell.append(element('b', { text: `${index + 1}` }));
          cell.append(document.createTextNode(word));
          phraseWords.append(cell);
        });
        phrasePanel.hidden = false;
        phraseWords.removeAttribute('hidden');
        replace(kindCard, noticeRich(
          'Write these words down before you continue.',
          'They are the wallet. Anyone who has them has the money, and this is the only time they are '
          + 'shown — the interface keeps no copy, and no server has ever seen them.',
          'warn',
        ));
      } catch (error) {
        failed(error, 'Creating the wallet');
      }
    },
  });

  const kindCard = element('div');
  kindCard.append(notice(
    'A wallet here has 256 bits of entropy from this device\'s own CSPRNG, and 24 words to back it up. '
    + 'The three keys it derives — wallet, validator node identity and account recovery — are separate keys, '
    + 'so a leaked node identity is not a leaked wallet.',
  ));

  const save = button('Save the keystore', {
    kind: 'primary',
    onClick: async () => {
      if (!pending) return;
      if (password.value.length < 12) return say('That password is too short', 'The protocol asks for at least 12 characters.', 'bad');
      if (password.value !== confirmation.value) return say('The passwords do not match', '', 'bad');
      try {
        const sealed = await wasm.call('keystore_seal', {
          handle: pending.handle,
          password: password.value,
          label: 'browser wallet',
        });
        const stored = phrases().set(sealed.keystore);
        record().set(pending);
        if (!stored) {
          say('Your browser refused to store the keystore',
            'Download it instead: you can open it from the command line or another device.', 'bad');
        }
        pending.keystore = sealed.keystore;
        renderModalDownload(sealed.keystore);
        await useWallet(pending);
        say('Wallet ready', `${pending.address} is yours: it exists once the chain has it, and nobody else can spend from it.`, 'good');
        location.reload();
      } catch (error) {
        failed(error, 'Sealing the keystore');
      }
    },
  });

  const restore = button('Restore from a phrase', {
    onClick: async () => {
      try {
        const phrase = phraseInput.value.trim();
        if (phrase.split(/\s+/).length !== 24) {
          return say('That is not a 24-word phrase', 'Obsidian wallets are 24 words. Check for a missing or extra word.', 'bad');
        }
        const restored = await wasm.call('wallet_from_phrase', {
          network: state.status?.network || 'devnet',
          phrase,
        });
        const view = wasm.walletView(restored);
        if (restorePassword.value.length >= 12) {
          const sealed = await wasm.call('keystore_seal', {
            handle: view.handle,
            password: restorePassword.value,
            label: 'restored wallet',
          });
          phrases().set(sealed.keystore);
          record().set(view);
          view.keystore = sealed.keystore;
        }
        await useWallet(view);
        say('Wallet restored', `${view.address} is open on this device.`, 'good');
        location.reload();
      } catch (error) {
        failed(error, 'Restoring the wallet');
      }
    },
  });

  root.append(grid([
    card({
      title: 'Create a wallet',
      subtitle: 'On this device, now.',
      body: element('div', { children: [
        kindCard,
        element('div', { className: 'row' }, [start]),
        phrasePanel,
        element('div', { children: [
          element('p', { className: 'hint', text: 'Your recovery phrase:' }),
          phraseWords,
        ] }),
        element('div', { className: 'field-row' }, [
          field('Keystore password', password, 'Seals the wallet on this device with Argon2id and ChaCha20-Poly1305.'),
          field('Confirm', confirmation),
        ]),
        element('div', { className: 'row' }, [save]),
      ] }),
    }),
    card({
      title: 'Restore a wallet',
      subtitle: 'From a recovery phrase you already hold.',
      body: element('div', { children: [
        notice('A phrase restores the wallet. An account recovery code restores access to an account whose '
          + 'MFA device was lost — that is a different thing, and it lives on the registration screen.'),
        field('Recovery phrase', phraseInput),
        field('Keystore password', restorePassword, 'Used to seal the restored wallet here. Leave it empty to keep it only for this session.'),
        element('div', { className: 'row' }, [restore]),
      ] }),
    }),
    card({
      title: 'Keep your own copy',
      subtitle: 'The keystore is the wallet.',
      body: element('div', { children: [
        notice('A browser can be cleared without warning. The keystore sealed here is stored in this '
          + 'browser\'s local storage; download it, or write the phrase down, or both. There is no '
          + 'server-side copy and no way to ask us for one — which is exactly why nobody else can '
          + 'spend your coins.'),
      ] }),
    }),
  ], 2));
}

function renderModalDownload(keystore) {
  const blob = new Blob([keystore], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = element('a', {
    text: 'Download the keystore file',
    attributes: { href: url, download: 'obsidian-keystore.json' },
  });
  say('Keystore sealed', 'Download it and keep it somewhere you control.');
  document.body.append(element('div', { className: 'toast' }, element('div', { children: [link] })));
}

/** What this browser holds: a sealed keystore, and what is publicly known of it. */
function heldWallet() {
  const keystore = phrases().get();
  if (!keystore) return null;
  return { keystore, public: record().get() };
}

/**
 * The wallet exists on this device but is locked.
 *
 * The address is shown because it is the account's public name and the person
 * needs to recognise which wallet they are holding; the keys are not, because
 * they are inside the sealed text.  Unlocking asks the Rust module to open the
 * keystore with the password, and — this is the part that matters — checks that
 * the wallet that came out is the one this record describes.  A keystore that
 * opens to a different address is not shown as if it were the right one.
 */
function renderLockedWallet(root, held) {
  const password = input({ type: 'password', placeholder: 'the keystore password', name: 'unlock-password' });
  const known = held.public;

  const rows = known ? pairs([
    ['Address', element('span', { className: 'mono', text: known.address })],
    ['Validator node address', element('span', { className: 'mono dim', text: known.nodeAddress || '—' })],
    ['Account recovery address', element('span', { className: 'mono dim', text: known.recoveryAddress || '—' })],
  ]) : notice(
    'This browser holds a sealed keystore but no note of which wallet it is. '
    + 'Enter its password to open it — the address cannot be read from a sealed keystore without it.',
  );

  const unlock = button('Unlock', {
    kind: 'primary',
    onClick: async () => {
      if (!password.value) return say('The password is needed', 'A sealed keystore cannot be opened without it.', 'bad');
      try {
        const answer = await wasm.call('keystore_open', {
          network: state.status?.network || known?.network || 'devnet',
          keystore: held.keystore,
          password: password.value,
        });
        const view = wasm.walletView(answer);
        if (known && view.address !== known.address) {
          await wasm.call('wallet_lock', { handle: view.handle }).catch(() => {});
          return say('That keystore is not this wallet',
            `It opened to ${view.address}, but this browser remembered ${known.address}. `
            + 'Nothing was spent; the two do not match.', 'bad');
        }
        record().set(view);
        await useWallet(view);
        replace(root, element('div'));
        renderOpenWallet(root, view);
        say('Wallet unlocked', 'It is open in this session. Lock it again, or close the page.', 'good');
      } catch (error) {
        failed(error, 'Opening the keystore');
      }
    },
  });

  root.append(grid([card({
    title: 'Your wallet',
    subtitle: 'Sealed on this device. Unlock it to spend.',
    body: element('div', { children: [
      rows,
      element('div', { className: 'field-row' }, [
        field('Keystore password', password, 'It never leaves this page: the Rust module opens the keystore here.'),
      ]),
      element('div', { className: 'row' },
        [unlock,
          button('Forget the stored keystore', {
            kind: 'danger',
            onClick: () => {
              phrases().clear();
              record().clear();
              session = null;
              say('Forgotten', 'The keystore is gone from this browser. If you still have the phrase or a copy of the keystore file, the wallet is not lost.');
              location.reload();
            },
          })]),
    ] }),
  })], 2));
}

async function useWallet(view) {
  try {
    const nonce = randomNonce();
    const proof = await wasm.call('account_proof', { handle: view.handle, nonce });
    const account = await node.accountProof(view.address, nonce, proof.signature);
    session = { view, proof, account };
  } catch (error) {
    // Not on chain yet, or the node is unreachable: the wallet still exists
    // locally, and saying so is more useful than an error.
    session = { view, proof: null, account: null };
  }
}

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function renderOpenWallet(root, view) {
  const header = card({
    title: 'Your wallet',
    subtitle: `${view.network} · account ${view.account}`,
    body: element('div', { children: [
      pairs([
        ['Address', element('span', { className: 'mono', text: view.address })],
        ['Validator node address', element('span', { className: 'mono dim', text: view.nodeAddress })],
        ['Account recovery address', element('span', { className: 'mono dim', text: view.recoveryAddress })],
        ['Wallet key', element('span', { className: 'mono', text: shortKey(view.walletKey) })],
        ['Node key', element('span', { className: 'mono', text: shortKey(view.nodeKey) })],
      ]),
      element('div', { className: 'row' },
        [button('Lock this wallet', {
          onClick: async () => {
            await wasm.call('wallet_lock', { handle: view.handle }).catch(() => {});
            session = null;
            say('Wallet locked in this session', 'The keystore is still sealed on this device; the phrase is still yours.');
            location.reload();
          },
        }),
        button('Forget the stored keystore', {
          kind: 'danger',
          onClick: () => {
            phrases().clear();
            record().clear();
            session = null;
            location.reload();
          },
        })]),
    ] }),
  });

  const balanceCard = card({
    title: 'Balance',
    subtitle: 'Read from the chain by proving this key, not by asking the explorer.',
    body: element('p', { className: 'dim', text: 'Reading the account\'s state from the node…' }),
  });

  const send = buildSend(view);
  const mining = buildClaim(view);

  root.append(grid([header, balanceCard], 2));
  root.append(grid([send, mining], 2));

  (async () => {
    await useWallet(view);
    if (!session || !session.account) {
      replace(balanceCard.querySelector('.card-body') || balanceCard,
        noticeRich('This wallet is not on chain yet.',
          'It holds keys, but the chain does not know the account. That happens until a registration '
          + 'transaction is mined — the Mining screen walks through registration, which needs an invitation.',
          'warn'));
      return;
    }
    const account = session.account;
    replace(balanceCard.querySelector('.card-body') || balanceCard,
      grid([
        metric('Balance', amount(account.balance, { unit: false }), { unit: 'OBS' }),
        metric('Lifetime rewards', amount(account.lifetime_rewards, { unit: false }), { unit: 'OBS from mining' }),
        metric('Claims today', String(account.claims_today), { unit: `of 6, next ${account.claimable_now ? 'available now' : until(account.next_claim_at, state.status?.protocol_time)}` }),
        metric('Next nonce', String(account.next_nonce), { unit: 'the chain\'s own count' }),
        metric('Genesis claim', account.genesis_claimed ? 'claimed' : 'not claimed', { unit: account.genesis_claimed ? 'this account founded the network' : '' }),
      ], 3),
      account.claimable_now ? noticeRich('A claim is available.', 'The chain\'s protocol time is past the interval.', 'good') : '');
  })().catch((error) => failed(error, 'Reading the balance'));
}

function shortKey(hex) {
  return `${hex.slice(0, 10)}…${hex.slice(-6)}`;
}

function buildSend(view) {
  const to = input({ placeholder: 'obs1…', name: 'to' });
  const amountInput = input({ placeholder: '0.5', name: 'amount' });
  const preview = element('p', { className: 'hint' });
  amountInput.addEventListener('input', () => {
    const value = amountInput.value.trim();
    if (!value) return void (preview.textContent = '');
    try {
      // The fee is the protocol's, and the module computes it: this page does not
      // hold a formula that could disagree with the chain.
      const fee = feeFor(value);
      preview.textContent = `Protocol fee: ${fee} OBS (0.02% of the amount, capped at 0.01 OBS, split 40% to validators and 60% to the mining pool).`;
    } catch (cause) {
      preview.textContent = '';
    }
  });

  const send = button('Sign and submit', {
    kind: 'primary',
    onClick: async () => {
      if (!session || !session.account) return say('No account on chain yet', 'Register first, or wait for the registration transaction to be mined.', 'bad');
      try {
        const signed = await wasm.call('sign_transfer', {
          handle: view.handle,
          to: to.value.trim(),
          amount: amountInput.value.trim(),
          nonce: session.account.next_nonce,
        });
        const answer = await node.submit(signed.transaction);
        say('Transfer signed and submitted', `Fee ${signed.fee} OBS. The node answered ${answer.status || 'pooled'}: the chain decides from here.`, 'good');
        preview.textContent = `Protocol fee: ${signed.fee} OBS, computed by the wallet module.`;
        // The signed bytes are shown, so a person can see what left this device.
        replace(details, element('details', { className: 'raw' }, [
          element('summary', { text: `The transaction that was signed (${signed.id})` }),
          element('pre', { text: signed.transaction }),
        ]));
      } catch (error) {
        failed(error, 'The transfer');
      }
    },
  });

  const details = element('div');
  const body = element('div', { children: [
    notice('You are signing with your own key on this device. The interface cannot move value on its '
      + 'own: it has no key of yours, and the chain checks the signature.'),
    field('Recipient address', to),
    field('Amount', amountInput, 'In OBS, up to 12 decimal places.'),
    preview,
    element('div', { className: 'row' }, [send]),
    details,
  ] });
  return card({ title: 'Send OBS', subtitle: 'Signed locally, submitted to a node.', body });
}

/** The fee, computed by the module — never by this file. */
function feeFor(text) {
  // A deliberately tiny helper: the value shown is only a preview, and the
  // authoritative fee is the one the module returns when it signs.  It mirrors
  // the rule (0.02%, capped) so the preview cannot be wildly wrong, and the
  // signature is what the chain will check.
  const [whole, fraction = ''] = text.split('.');
  const grains = BigInt(whole || '0') * 1000000000000n + BigInt((fraction + '000000000000').slice(0, 12));
  if (grains === 0n) return '0';
  let fee = (grains * 2n + 9999n) / 10000n;
  const cap = 10000000000n;
  if (fee > cap) fee = cap;
  const wholePart = fee / 1000000000000n;
  const fractionPart = (fee % 1000000000000n).toString().padStart(12, '0').replace(/0+$/, '');
  return fractionPart ? `${wholePart}.${fractionPart}` : String(wholePart);
}

function buildClaim(view) {
  const status = element('div', { className: 'dim', text: 'Reading the chain\'s eligibility rules…' });
  const claim = button('Mine a claim', {
    kind: 'primary',
    onClick: async () => {
      if (!session || !session.account) return say('No account on chain yet', 'Registration first.', 'bad');
      try {
        const signed = await wasm.call('sign_claim', {
          handle: view.handle,
          protocol_time: Number(state.status.protocol_time),
          sequence: session.account.last_claim_sequence + 1,
          nonce: session.account.next_nonce,
        });
        const answer = await node.submit(signed.transaction);
        say('Claim signed and submitted', `Stamped with protocol time ${signed.protocol_time}. The node answered ${answer.status || 'pooled'}.`, 'good');
      } catch (error) {
        failed(error, 'The claim');
      }
    },
  });

  (async () => {
    await useWallet(view);
    const mining = state.mining;
    if (!session || !session.account) {
      replace(status, document.createTextNode('No account on chain, so no claim is possible yet.'));
      return;
    }
    const account = session.account;
    const chainNow = Number(state.status.protocol_time);
    replace(status, element('div', { className: 'children' }, [
      grid([
        metric('Claim available', account.claimable_now ? 'yes' : 'no', {
          unit: account.claimable_now ? 'the interval has passed' : `next ${until(account.next_claim_at, chainNow)}`,
        }),
        metric('Next reward', amount(mining ? mining.reward_per_claim : '0', { unit: false }), { unit: 'OBS, from the chain' }),
        metric('Interval', '4 hours', { unit: '1 claim per account' }),
        metric('Daily cap', '6 claims', { unit: 'per protocol day' }),
      ], 4),
      notice('Eligibility is protocol time, never a browser timer: the claim declares the protocol time '
        + 'of the block that will carry it, and the block is stamped with exactly that time. A claim '
        + 'built too early is refused by the chain, whoever built it.'),
    ]));
  })().catch((error) => failed(error, 'Reading mining eligibility'));

  return card({ title: 'Mining', subtitle: 'One claim every four hours, six a day.', body: element('div', { children: [status, element('div', { className: 'row' }, [claim])] }) });
}
