// Mining: registering an account, and claiming with it.
//
// Mining on Obsidian is not a race and has no hash puzzles.  A claim is a signed
// statement that a registered account's four-hour interval has passed, and
// eligibility comes from protocol time — the timestamp of the block that carries
// the claim — so nothing here depends on this machine's clock.  The interface
// shows what the chain says, and a browser timer is informational at best.
//
// Registration is the six-step flow, and the wallet is created *here* first: the
// last step hands the registration service three public keys.  That is what makes
// the account non-custodial from its first moment — the service never has a key
// that can move value, and it could not create an account on somebody else's key
// because the wallet signs the registration transaction itself.

import { accounts, describe, node } from '../api.js';
import { amount, element, moment, until } from '../format.js';
import { state } from '../state.js';
import { button, card, field, grid, input, metric, notice, noticeRich, pairs, pill, raw, replace, table } from '../ui.js';
import { failed, say } from '../app.js';
import * as wasm from '../wasm.js';

export const title = 'Mining';

const steps = [
  ['gmail', 'Gmail address'],
  ['password', 'Password'],
  ['invite', 'Invitation code'],
  ['recovery', 'Account recovery code'],
  ['mfa', 'Authenticator (MFA)'],
  ['wallet', 'Wallet keys'],
  ['activated', 'Activated'],
];

export async function render(root) {
  root.append(element('div', { className: 'hero' },
    element('h1', { text: 'Mining' }),
    element('p', {
      text: 'Proof of time, not proof of work: no hash puzzles, no race, no advantage from buying '
        + 'hardware. A registered account may claim once every four hours, six times a day, and the '
        + 'reward is fixed by the protocol and halved as the network grows.',
    })));

  const [mining, supply] = await Promise.all([
    node.mining().catch(() => state.mining),
    node.supply().catch(() => state.supply),
  ]);

  root.append(grid([
    metric('Reward per claim', amount(mining.reward_per_claim, { unit: false }), { unit: 'OBS, every 4 hours' }),
    metric('Daily rate', amount(mining.daily_rate, { unit: false }), { unit: 'OBS per day' }),
    metric('Active miners', String(mining.active_miners), { unit: 'claimed within 30 days' }),
    metric('Claims issued', String(mining.claims_issued), { unit: 'since genesis' }),
    metric('Genesis claim', mining.genesis_claim_issued ? 'issued' : 'available', {
      unit: mining.genesis_claim_issued ? 'the treasury holds it' : `first claim takes ${amount(supply.genesis_allocation)}`,
    }),
    metric('Halving', '-0.5%', { unit: 'per 100,000 active miners, with a floor' }),
  ], 3));

  root.append(card({
    title: 'How a claim is judged',
    subtitle: 'By the chain, from protocol time.',
    body: element('div', { children: [
      table(['Rule', 'Value'], [
        ['Interval between claims', '4 hours (14,400 seconds of protocol time)'],
        ['Claims per protocol day', '6'],
        ['Eligibility clock', 'the block\'s timestamp — never a browser timer'],
        ['Reward for the next claim', `${amount(mining.reward_per_claim)} OBS`],
        ['Fee to claim', 'none — a claim is not a transaction with a fee'],
      ].map(([rule, value]) => [
        element('td', { className: 'dim', text: rule }),
        element('td', { text: value }),
      ])),
      notice('A claim declares the protocol time of the block that will carry it, and the chain accepts '
        + 'it in that block and no other. If this network\'s protocol time is behind your wall clock, the '
        + 'chain is right and the clock is not.'),
    ] }),
  }));

  root.append(registrationCard(root));
  root.append(claimCard());
  root.append(signInCard());
  root.append(inviteCard());
}

function registrationCard(root) {
  const status = element('div');
  const progress = element('ol', { className: 'steps' });
  const stage = { current: 'gmail' };
  let token = null;
  let wallet = null;
  let secrets = null;

  const fields = {
    gmail: input({ placeholder: 'you@gmail.com', name: 'gmail' }),
    password: input({ type: 'password', placeholder: 'at least 12 characters', name: 'password' }),
    invite: input({ placeholder: 'OBS-XXXX-XXXX-XXXX-XXXX', name: 'invite' }),
    mfa: input({ placeholder: 'six digits from your authenticator', name: 'mfa' }),
  };

  function paint() {
    progress.replaceChildren();
    for (const [key, label] of steps) {
      const done = steps.findIndex(([name]) => name === key) < steps.findIndex(([name]) => name === stage.current);
      const active = key === stage.current;
      progress.append(element('li', {
        text: label,
        attributes: { 'data-state': active ? 'active' : done ? 'done' : 'todo' },
      }));
    }
  }

  const panel = element('div');
  paint();

  const run = button('Begin registration', {
    kind: 'primary',
    onClick: async () => {
      try {
        switch (stage.current) {
          case 'gmail': {
            const gmail = fields.gmail.value.trim();
            const begun = await accounts.begin(gmail);
            token = begun.token;
            stage.current = 'password';
            say('Gmail accepted', 'No email verification code is used: the address is canonicalised on the server, and one Gmail identity can hold exactly one account.', 'good');
            break;
          }
          case 'password': {
            if (fields.password.value.length < 12) {
              return say('That password is too short', 'The protocol asks for at least 12 characters.', 'bad');
            }
            await accounts.password(token, fields.password.value);
            stage.current = 'invite';
            break;
          }
          case 'invite': {
            await accounts.invite(token, fields.invite.value.trim());
            stage.current = 'recovery';
            break;
          }
          case 'recovery': {
            const step = await accounts.recoveryCode(token);
            secrets = { ...(secrets || {}), recovery_code: step.value };
            stage.current = 'mfa';
            say('Account recovery code issued', 'It is shown once: it restores access to this account if you lose your authenticator. It is not the wallet recovery phrase.', 'good');
            break;
          }
          case 'mfa': {
            if (!secrets?.secret) {
              const step = await accounts.enrolMfa(token);
              secrets = { ...secrets, secret: step.value };
              replace(panel, mfaPanel(secrets));
              return;
            }
            await accounts.confirmMfa(token, fields.mfa.value.trim());
            stage.current = 'wallet';
            break;
          }
          case 'wallet': {
            if (!wallet) {
              const created = await wasm.call('wallet_generate', { network: state.status?.network || 'devnet' });
              wallet = wasm.walletView(created);
            }
            const activated = await accounts.attachWallet(token, wallet);
            stage.current = 'activated';
            replace(panel, activatedPanel(activated, wallet, secrets));
            say('Account activated', 'Mining is enabled for this account.', 'good');
            break;
          }
          default:
            break;
        }
        paint();
        replace(panel, stagePanel(stage.current, fields, wallet, secrets));
      } catch (error) {
        failed(error, 'Registration');
      }
    },
  });

  replace(panel, stagePanel(stage.current, fields, wallet, secrets));
  return card({
    title: 'Register an account',
    subtitle: 'Gmail → password → invitation → recovery code → MFA → wallet. No email code.',
    body: element('div', { children: [progress, panel, element('div', { className: 'row' }, [run])] }),
  });
}

function stagePanel(stage, fields, wallet, secrets) {
  switch (stage) {
    case 'gmail':
      return element('div', { children: [
        notice('A Gmail address is required: the protocol canonicalises it (lower-case, dots and +tags '
          + 'removed, googlemail.com mapped to gmail.com) and records only a commitment to the result. '
          + 'One canonical Gmail identity can hold exactly one account, enforced atomically by the '
          + 'registration service, and there is no email verification step.'),
        field('Gmail address', fields.gmail),
      ] });
    case 'password':
      return element('div', { children: [
        notice('The password is hashed with Argon2id and never stored or transmitted in the clear. It '
          + 'protects the account; it does not protect your coins — your keys do that, and they never '
          + 'leave this device.'),
        field('Password', fields.password),
      ] });
    case 'invite':
      return element('div', { children: [
        notice('Obsidian is invitation-gated. An account may issue up to five invitations of its own. '
          + 'An invitation is single-use and is spent atomically: two people redeeming the same code '
          + 'at the same moment cannot both succeed.'),
        field('Invitation code', fields.invite),
      ] });
    case 'recovery':
      return element('div', { children: [
        noticeRich('Your account recovery code will be shown once.',
          'It restores access to this account — not to your coins. Your wallet has its own recovery '
          + 'phrase, and the two are deliberately separate: losing one does not hand over the other.',
          'warn'),
      ] });
    case 'mfa':
      return element('div', { children: [
        notice('Scan the secret with your authenticator app, or enter it by hand, then confirm with a '
          + 'code. The secret is sealed at rest with the service key and is never logged.'),
        field('Authenticator code', fields.mfa),
      ] });
    case 'wallet':
      return element('div', { children: [
        noticeRich('Your wallet keys are created on this device.',
          'The registration service is given three public keys — wallet, validator node identity and '
          + 'account recovery — and no private key, ever. The account exists on chain once the wallet '
          + 'has signed the registration transaction, and the chain checks that signature.',
          'good'),
      ] });
    case 'activated':
      return element('div', { children: [
        noticeRich('The account is activated and mining is enabled.',
          'The wallet must still sign its registration transaction and have it mined before the account '
          + 'exists on chain. The Wallet screen does that and shows the balance once the chain has it.',
          'good'),
      ] });
    default:
      return element('div');
  }
}

function mfaPanel(secrets) {
  const uri = `otpauth://totp/Obsidian?secret=${secrets.secret}&issuer=Obsidian`;
  return element('div', { children: [
    element('p', { className: 'hint', text: 'Authenticator secret (shown once):' }),
    element('div', { className: 'secret', text: secrets.secret }),
    element('p', { className: 'hint', text: 'Or scan this URI as a QR code:' }),
    element('div', { className: 'secret', text: uri }),
    element('p', { className: 'hint', text: 'Store it offline with the recovery code. Anyone with it can generate your codes.' }),
  ] });
}

function activatedPanel(activated, wallet, secrets) {
  return element('div', { children: [
    pairs([
      ['Address', element('span', { className: 'mono', text: wallet?.address || '—' })],
      ['Gmail commitment', element('span', { className: 'mono', text: activated.gmail_commitment || '—' })],
      ['Mining enabled', pill('yes', 'green')],
    ]),
    element('p', { className: 'hint', text: 'Your recovery code and authenticator secret were shown once. This interface keeps no copy of either.' }),
    raw('The registration service\'s answer', activated),
  ] });
}

function claimCard() {
  return card({
    title: 'Claim with an account',
    subtitle: 'The wallet signs; the chain decides.',
    body: element('div', { children: [
      notice('Open the Wallet screen and use "Mine a claim" — the wallet reads the chain\'s own count of '
        + 'your claims and its protocol time, stamps the claim with that time, signs it here and hands '
        + 'the signed bytes to a node.'),
      table(['What a claim is', 'What a claim is not'], [
        ['a signed statement that a registered account\'s interval has passed', 'a hash puzzle, a race or a bid for a fee'],
        ['judged against the block\'s protocol time', 'judged against your computer\'s clock'],
        ['one per account per four hours, six per day', 'unlimited, or improvable by buying hardware'],
      ].map(([is, not]) => [
        element('td', { text: is }),
        element('td', { className: 'dim', text: not }),
      ])),
    ] }),
  });
}

function signInCard() {
  const gmail = input({ placeholder: 'you@gmail.com', name: 'signin-gmail' });
  const password = input({ type: 'password', name: 'signin-password' });
  const code = input({ placeholder: 'six digits', name: 'signin-code' });
  const answer = element('div');
  const signIn = button('Sign in', {
    onClick: async () => {
      try {
        const session = await accounts.signIn(gmail.value.trim(), password.value, code.value.trim());
        // The session token is a bearer credential for the account; it lives in
        // memory for this tab and is not written to storage.
        window.__obsSession = session.token;
        const me = await accounts.me(session.token);
        replace(answer, pairs([
          ['Signed in as', element('span', { className: 'mono', text: me.gmail || 'account' })],
          ['Invitations used', String(me.invites_issued ?? 0)],
          ['Invitations left', String(me.invites_remaining ?? '—')],
          ['Session expires', moment(session.expires_at)],
        ]));
        say('Signed in', 'The session lasts twelve hours and is held in this tab only.', 'good');
      } catch (error) {
        failed(error, 'Sign in');
      }
    },
  });
  return card({
    title: 'Sign in',
    subtitle: 'Password plus authenticator code.',
    body: element('div', { children: [
      element('div', { className: 'field-row' }, [
        field('Gmail', gmail), field('Password', password), field('Authenticator code', code),
      ]),
      element('div', { className: 'row' }, [signIn]),
      answer,
    ] }),
  });
}

function inviteCard() {
  const answer = element('div');
  const list = button('Show my invitations', {
    onClick: async () => {
      const token = window.__obsSession;
      if (!token) return say('Sign in first', 'Invitations belong to an account.', 'bad');
      try {
        const invites = await accounts.invites(token);
        replace(answer, table(['Code', 'Issued', 'Expires', 'Redeemed'],
          (invites.invites || []).map((invite) => [
            element('td', { className: 'mono', text: invite.code || '(hidden)' }),
            element('td', { className: 'mono dim', text: moment(invite.issued_at) }),
            element('td', { className: 'mono dim', text: moment(invite.expires_at) }),
            element('td', {}, pill(invite.redeemed ? 'yes' : 'no', invite.redeemed ? 'dim' : 'green')),
          ]), { empty: 'You have not issued an invitation yet.' }));
      } catch (error) {
        failed(error, 'Listing invitations');
      }
    },
  });
  const issue = button('Issue one invitation', {
    kind: 'primary',
    onClick: async () => {
      const token = window.__obsSession;
      if (!token) return say('Sign in first', 'Invitations are spent from an account\'s own budget.', 'bad');
      try {
        const issued = await accounts.issueInvite(token);
        say('Invitation issued', 'Give it to one person, out of band. It is single-use and cannot be re-issued if lost.', 'good');
        replace(answer, element('div', { children: [
          element('p', { className: 'hint', text: 'The code, shown once:' }),
          element('div', { className: 'secret', text: issued.code || issued.invite || '(see the service)' }),
        ] }));
      } catch (error) {
        failed(error, 'Issuing an invitation');
      }
    },
  });
  return card({
    title: 'Your invitations',
    subtitle: 'Five per account, single-use, spent atomically.',
    body: element('div', { children: [
      element('div', { className: 'row' }, [issue, list]),
      answer,
    ] }),
  });
}
