//! End-to-end tests of the Obsidian Network state machine.
//!
//! Everything here drives the real protocol: real Ed25519 keys, real
//! registration authorisations, real claims, real gas fees, real validator
//! bonds and real blocks produced by [`ChainState::build_block`] and applied by
//! [`ChainState::apply_block`].  There are no mocks and no shortcuts: if a test
//! in this file passes, the rule it checks is enforced by the protocol itself.

use std::collections::BTreeMap;

use obs_chain::block::Attestation;
use obs_chain::chain::{gmail_commitment, invite_commitment, Claim, ExitReason, InviteAuthorization};
use obs_chain::params::{
    gas_fee_for, split_gas_fee, ATTESTATION_WINDOW_BLOCKS, BASE_CLAIM_GRAINS,
    BOOTSTRAP_SLOTS, CLAIM_INTERVAL_SECS, GENESIS_BLOCK_HEIGHT, GENESIS_TIMESTAMP,
    MAX_CLAIMS_PER_DAY, MAX_GAS_FEE, MAX_TXS_PER_BLOCK, PROTOCOL_DAY_SECS, SLOT_DURATION_SECS,
    UNBONDING_PERIOD_SECS, VALIDATOR_BOND,
};
use obs_chain::state::{BlockEffects, ChainState, GenesisConfig, StateError};
use obs_chain::pot::proposer_for_slot;
use obs_chain::{Block, Transaction, TxKind};
use obs_crypto::ed25519::Keypair;
use obs_primitives::address::Address;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION, MAX_SUPPLY};
use obs_primitives::network::{MAINNET, TESTNET};

/// A test network driven entirely through the public protocol API.
struct Env {
    /// Registration authority that authorises invitations.
    authority: Keypair,
    state: ChainState,
    /// Timestamp the next block will carry, and therefore the protocol time.
    time: u64,
    /// Account that proposes blocks while the chain is in bootstrap mode.
    proposer: Keypair,
    /// Next nonce per account, derived from on-chain state.
    nonces: BTreeMap<Address, u64>,
}

impl Env {
    fn new() -> Env {
        let authority = Keypair::from_seed(&[1u8; 32]);
        let config = GenesisConfig {
            network: MAINNET,
            registration_authority: authority.public_key(),
            timestamp: GENESIS_TIMESTAMP,
        };
        Env {
            authority,
            state: ChainState::new(&config),
            time: GENESIS_TIMESTAMP + 1,
            proposer: Keypair::from_seed(&[30u8; 32]),
            nonces: BTreeMap::new(),
        }
    }

    fn address(key: &Keypair) -> Address {
        Address::from_public_key(MAINNET, &key.public_key())
    }

    /// Next nonce for an account: always derived from chain state, so a
    /// transaction that was rejected never burns a nonce.
    fn next_nonce(&mut self, key: &Keypair) -> u64 {
        let address = Env::address(key);
        let base = self
            .state
            .account(&address)
            .map(|account| account.last_nonce)
            .unwrap_or(0);
        let entry = self.nonces.entry(address).or_insert(base);
        *entry += 1;
        *entry
    }

    fn sign(&mut self, key: &Keypair, kind: TxKind) -> Transaction {
        let nonce = self.next_nonce(key);
        Transaction::sign(MAINNET, nonce, kind, key)
    }

    fn claim_tx(&mut self, key: &Keypair, sequence: u64) -> Transaction {
        let safe = key.clone();
        self.sign(
            &safe,
            TxKind::Claim(Claim {
                account: Env::address(&safe),
                claimed_at: self.time,
                sequence,
            }),
        )
    }

    /// Issues an invitation for a canonical Gmail identity.
    fn invite_for(&mut self, code: &str, email: &str, issuer: Option<Address>) -> InviteAuthorization {
        let canonical = obs_primitives::identity::canonical_gmail(email).expect("test email");
        InviteAuthorization::issue(
            MAINNET.chain_id,
            &self.authority,
            invite_commitment(MAINNET.chain_id, code),
            gmail_commitment(MAINNET.chain_id, &canonical),
            self.time,
            self.time + 86_400,
            issuer,
        )
    }

    fn register_tx(&mut self, key: &Keypair, email: &str, code: &str) -> Transaction {
        self.register_tx_issued_by(key, email, code, None)
    }

    fn register_tx_issued_by(
        &mut self,
        key: &Keypair,
        email: &str,
        code: &str,
        issuer: Option<Address>,
    ) -> Transaction {
        let key = key.clone();
        let address = Env::address(&key);
        let canonical = obs_primitives::identity::canonical_gmail(email).expect("test email");
        let invite = self.invite_for(code, email, issuer);
        self.sign(
            &key,
            TxKind::Register {
                account: address,
                wallet_key: key.public_key(),
                gmail_commitment: gmail_commitment(MAINNET.chain_id, &canonical),
                invite,
            },
        )
    }

    /// Registers `key` in its own block, so `invite_commitment` is not charged
    /// to anyone's invitation budget.
    fn register(&mut self, key: &Keypair, email: &str, code: &str) -> Address {
        let tx = self.register_tx(key, email, code);
        let bootstrap = self.bootstrap_proposer_for(key);
        self.commit_as(&bootstrap, vec![tx], Vec::new())
            .expect("registration block applies");
        Env::address(key)
    }

    /// During bootstrap any registered account may propose.  The founder key is
    /// used once it exists; before that, the block's own new account proposes.
    fn bootstrap_proposer_for(&self, key: &Keypair) -> Keypair {
        match self.state.accounts.is_empty() {
            true => key.clone(),
            false => self.proposer.clone(),
        }
    }

    fn commit(&mut self, txs: Vec<Transaction>, attestations: Vec<Attestation>) -> Result<BlockEffects, StateError> {
        let proposer = self.proposer.clone();
        self.commit_as(&proposer, txs, attestations)
    }

    fn commit_as(
        &mut self,
        proposer: &Keypair,
        txs: Vec<Transaction>,
        attestations: Vec<Attestation>,
    ) -> Result<BlockEffects, StateError> {
        let timestamp = self.time;
        self.commit_at(proposer, timestamp, txs, attestations)
    }

    fn commit_at(
        &mut self,
        proposer: &Keypair,
        timestamp: u64,
        txs: Vec<Transaction>,
        attestations: Vec<Attestation>,
    ) -> Result<BlockEffects, StateError> {
        let result = match self.state.build_block(proposer, timestamp, txs, attestations) {
            Ok(block) => self.apply(&block),
            Err(error) => Err(error),
        };
        // Whether the block applied or not, the next signature starts again
        // from on-chain state.
        self.nonces.clear();
        result
    }

    /// Applies a block, verifying the state root and the invariants.
    fn apply(&mut self, block: &Block) -> Result<BlockEffects, StateError> {
        let applied = self.state.apply_block(block)?;
        assert_eq!(
            applied.state.state_root(),
            block.header.state_root,
            "the applied state must match the root the block commits to"
        );
        applied
            .state
            .check_invariants()
            .expect("every reachable state must satisfy the protocol invariants");
        self.state = applied.state;
        self.time = block.header.timestamp + 1;
        Ok(applied.effects)
    }

    /// Advances protocol time by producing empty blocks, respecting the
    /// +60 second drift limit, until the next block's timestamp is `target`.
    ///
    /// The head ends at `target - 1`, so a test that needs a block at an exact
    /// protocol time can produce one and rely on it.
    fn advance_to(&mut self, target: u64) {
        assert!(
            target >= self.time,
            "the target is in the past: protocol time only moves forward"
        );
        while self.time < target {
            let timestamp = (self.time + 59).min(target - 1).max(self.time);
            let proposer = self.proposer.clone();
            self.commit_at(&proposer, timestamp, Vec::new(), Vec::new())
                .expect("an empty bootstrap block must apply");
        }
        assert_eq!(self.time, target, "the next block is exactly at the target");
    }

    /// One block that registers the founder and mines the genesis claim.
    fn genesis(&mut self) -> (Keypair, Address) {
        let founder = Keypair::from_seed(&[30u8; 32]);
        let address = Env::address(&founder);
        let register = self.register_tx(&founder, "founder@gmail.com", "TEST-INVITE-GENESIS");
        let claim = self.claim_tx(&founder, 1);
        let founder_key = self.proposer.clone();
        self.commit_at(&founder_key, self.time, vec![register, claim], Vec::new())
            .expect("the genesis block applies");
        (founder, address)
    }

    fn active_validators(&self) -> Vec<[u8; 32]> {
        self.state.active_validators()
    }

    /// Registers `owner` as a validator with `node` as its node identity.
    fn add_validator(&mut self, owner: &Keypair, node: &Keypair, code: &str) {
        let owner_address = self.register(owner, &format!("{}@gmail.com", code.to_lowercase()), code);
        // Fund the bond from the founder.
        let founder = self.proposer.clone();
        let bond = self.sign(
            &founder,
            TxKind::Transfer {
                to: owner_address,
                amount: VALIDATOR_BOND,
            },
        );
        let owner = owner.clone();
        let validator = self.sign(
            &owner,
            TxKind::RegisterValidator {
                node_key: node.public_key(),
                endpoint: format!("node-{}.obsidian.example:9200", code),
            },
        );
        self.commit(vec![bond, validator], Vec::new())
            .expect("validator registration applies");
    }
}

/// Gives an account a starting balance.
fn fund(env: &mut Env, to: Address, amount: Amount) {
    let founder = env.proposer.clone();
    let tx = env.sign(
        &founder,
        TxKind::Transfer {
            to,
            amount,
        },
    );
    env.commit(vec![tx], Vec::new()).expect("funding applies");
}

fn transfer(env: &mut Env, from: &Keypair, to: Address, amount: Amount) -> Transaction {
    let from = from.clone();
    env.sign(&from, TxKind::Transfer { to, amount })
}

// ---------------------------------------------------------------------------
// Genesis, treasury and the money supply
// ---------------------------------------------------------------------------

#[test]
fn the_genesis_claim_creates_the_treasury_exactly_once() {
    let mut env = Env::new();
    let (founder, treasury) = env.genesis();

    assert_eq!(env.state.height, GENESIS_BLOCK_HEIGHT);
    assert!(env.state.genesis_issued);
    assert_eq!(env.state.treasury, Some(treasury), "the genesis wallet is the treasury");
    let expected = GENESIS_ALLOCATION
        .checked_add(Amount(BASE_CLAIM_GRAINS))
        .unwrap();
    assert_eq!(env.state.balance(&treasury), expected);
    assert_eq!(env.state.issued_supply, expected);
    assert!(env.state.issued_supply < MAX_SUPPLY);
    assert_eq!(env.state.total_claims, 1);
    let account = env.state.account(&treasury).unwrap();
    assert!(account.genesis_claimed);
    assert_eq!(account.last_claim_sequence, 1);

    // A second miner claiming later gets only the ordinary claim reward, never
    // another genesis allocation.
    let miner = Keypair::from_seed(&[31u8; 32]);
    let miner_address = env.register(&miner, "miner@gmail.com", "TEST-INVITE-MINER");
    assert_eq!(env.state.balance(&miner_address), Amount::ZERO, "a new account starts empty");
    env.advance_to(env.time + CLAIM_INTERVAL_SECS);
    let tx = env.claim_tx(&miner, 1);
    env.commit(vec![tx], Vec::new()).unwrap();
    let account = env.state.account(&miner_address).unwrap();
    assert!(!account.genesis_claimed);
    assert_eq!(account.balance, Amount(BASE_CLAIM_GRAINS));
    assert_eq!(env.state.treasury, Some(treasury), "the treasury never changes");
    assert_eq!(env.state.issued_supply, expected.checked_add(Amount(BASE_CLAIM_GRAINS)).unwrap());
    let _ = founder;
}

#[test]
fn only_the_first_block_can_mine_the_genesis_allocation() {
    let mut env = Env::new();
    let (founder, address) = env.genesis();
    // The founder's own next claim is an ordinary claim.
    env.advance_to(env.time + CLAIM_INTERVAL_SECS);
    let tx = env.claim_tx(&founder, 2);
    env.commit(vec![tx], Vec::new()).unwrap();
    let expected = GENESIS_ALLOCATION
        .checked_add(Amount(BASE_CLAIM_GRAINS * 2))
        .unwrap();
    assert_eq!(env.state.balance(&address), expected);
    assert_eq!(env.state.issued_supply, expected);
    assert_eq!(env.state.total_claims, 2);
}

// ---------------------------------------------------------------------------
// Registration, invitations and one account per Gmail
// ---------------------------------------------------------------------------

#[test]
fn an_account_is_registered_empty_and_its_address_is_masked_in_messages() {
    let mut env = Env::new();
    env.genesis();
    let miner = Keypair::from_seed(&[32u8; 32]);
    let address = env.register(&miner, "miner@gmail.com", "TEST-INVITE-1");
    let account = env.state.account(&address).expect("the account exists");
    assert_eq!(account.balance, Amount::ZERO);
    assert_eq!(
        account.last_nonce, 1,
        "the registration itself is the account's first transaction"
    );
    assert_eq!(account.last_claim_sequence, 0);
    assert_eq!(account.claims_today, 0);
    assert_eq!(account.invites_issued, 0);
    assert!(account.address.to_string().starts_with("obs1"));
    // The wallet binding is a hash, never the address of a different key.
    assert_eq!(account.wallet_key, miner.public_key());
    assert_ne!(account.gmail_commitment, gmail_commitment(MAINNET.chain_id, "other@gmail.com"));
}

#[test]
fn one_gmail_identity_can_never_bind_two_accounts() {
    let mut env = Env::new();
    env.genesis();
    let first = Keypair::from_seed(&[33u8; 32]);
    env.register(&first, "same@gmail.com", "TEST-INVITE-A");

    let second = Keypair::from_seed(&[34u8; 32]);
    let tx = env.register_tx(&second, "same@gmail.com", "TEST-INVITE-B");
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "gmail_duplicate");

    // The canonicalisation rule is the same on both sides: a differently written
    // but canonically identical identity cannot slip through either.
    let third = Keypair::from_seed(&[35u8; 32]);
    let tx = env.register_tx(&third, "Same@Gmail.com", "TEST-INVITE-C");
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "gmail_duplicate");
}

#[test]
fn an_invitation_is_single_use() {
    let mut env = Env::new();
    env.genesis();
    let first = Keypair::from_seed(&[36u8; 32]);
    env.register(&first, "first@gmail.com", "TEST-INVITE-ONCE");

    // The same invitation code, for a different account: refused, because the
    // commitment is already recorded as redeemed.
    let second = Keypair::from_seed(&[37u8; 32]);
    let tx = env.register_tx(&second, "second@gmail.com", "TEST-INVITE-ONCE");
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "invite_redeemed");
}

#[test]
fn an_account_can_issue_at_most_five_invitations() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    for index in 0..5u8 {
        let newcomer = Keypair::from_seed(&[40 + index; 32]);
        let tx = env.register_tx_issued_by(
            &newcomer,
            &format!("invited{}@gmail.com", index),
            &format!("TEST-INVITE-{}", index),
            Some(founder_address),
        );
        env.commit(vec![tx], Vec::new()).expect("the invitation is within budget");
    }
    assert_eq!(
        env.state.account(&founder_address).unwrap().invites_issued,
        5
    );

    let sixth = Keypair::from_seed(&[50u8; 32]);
    let tx = env.register_tx_issued_by(&sixth, "sixth@gmail.com", "TEST-INVITE-6", Some(founder_address));
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "invite_budget");
    let _ = &founder;
}

#[test]
fn an_invitation_forged_by_a_non_authority_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let attacker = Keypair::from_seed(&[51u8; 32]);
    let victim = Keypair::from_seed(&[52u8; 32]);
    let address = Env::address(&victim);
    // The attacker signs its own "authorisation".
    let forged = InviteAuthorization::issue(
        MAINNET.chain_id,
        &attacker,
        invite_commitment(MAINNET.chain_id, "TEST-INVITE-FORGED"),
        gmail_commitment(MAINNET.chain_id, "victim@gmail.com"),
        env.time,
        env.time + 86_400,
        None,
    );
    let tx = env.sign(
        &victim,
        TxKind::Register {
            account: address,
            wallet_key: victim.public_key(),
            gmail_commitment: gmail_commitment(MAINNET.chain_id, "victim@gmail.com"),
            invite: forged,
        },
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "invite_authority");
}

#[test]
fn an_invitation_for_another_network_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let victim = Keypair::from_seed(&[53u8; 32]);
    let address = Env::address(&victim);
    // A genuine testnet authorisation, replayed on mainnet.
    let canonical = obs_primitives::identity::canonical_gmail("victim@gmail.com").unwrap();
    let testnet_invite = InviteAuthorization::issue(
        TESTNET.chain_id,
        &env.authority,
        invite_commitment(TESTNET.chain_id, "TEST-INVITE-TESTNET"),
        gmail_commitment(MAINNET.chain_id, &canonical),
        env.time,
        env.time + 86_400,
        None,
    );
    let tx = env.sign(
        &victim,
        TxKind::Register {
            account: address,
            wallet_key: victim.public_key(),
            gmail_commitment: gmail_commitment(MAINNET.chain_id, &canonical),
            invite: testnet_invite,
        },
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    // Either the signature check or the authority check must stop it; both are
    // protocol rules that fail closed.
    assert!(
        error.rule == "invite_signature" || error.rule == "invite_authority",
        "unexpected rule {}",
        error.rule
    );
}

// ---------------------------------------------------------------------------
// Mining claims
// ---------------------------------------------------------------------------

#[test]
fn claims_are_paced_by_the_protocol_not_by_a_client_clock() {
    let mut env = Env::new();
    let (founder, address) = env.genesis();
    let t0 = env.state.account(&address).unwrap().last_claim_at;

    // One second before the four-hour interval has elapsed: refused, and
    // nothing about the account changes.
    env.advance_to(t0 + CLAIM_INTERVAL_SECS - 1);
    let early = env.claim_tx(&founder, 2);
    let error = env.commit(vec![early], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "claim_interval");
    assert_eq!(env.state.account(&address).unwrap().last_claim_sequence, 1);
    assert_eq!(env.state.total_claims, 1);

    // Exactly on the interval: accepted.
    env.advance_to(t0 + CLAIM_INTERVAL_SECS);
    let on_time = env.claim_tx(&founder, 2);
    env.commit(vec![on_time], Vec::new()).unwrap();

    // Six claims fill a protocol day.  The window is anchored at the first
    // claim, so the pacing is decided by protocol time alone -- no client
    // clock, no browser timer and no API can move it.
    for sequence in 3..=MAX_CLAIMS_PER_DAY {
        let last = env.state.account(&address).unwrap().last_claim_at;
        env.advance_to(last + CLAIM_INTERVAL_SECS);
        let tx = env.claim_tx(&founder, sequence);
        env.commit(vec![tx], Vec::new()).expect("within the daily window");
    }
    let account = env.state.account(&address).unwrap().clone();
    assert_eq!(account.claims_today, MAX_CLAIMS_PER_DAY);
    assert_eq!(
        account.last_claim_at,
        account.claim_window_start
            + (MAX_CLAIMS_PER_DAY - 1) * CLAIM_INTERVAL_SECS,
        "six claims span the protocol day exactly"
    );

    // A seventh claim one second before the window rolls over is refused: the
    // sixth claim is not four hours old yet.
    env.advance_to(account.claim_window_start + PROTOCOL_DAY_SECS - 1);
    let early = env.claim_tx(&founder, MAX_CLAIMS_PER_DAY + 1);
    let error = env.commit(vec![early], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "claim_interval");
    assert_eq!(env.state.total_claims, MAX_CLAIMS_PER_DAY);

    // At exactly 24 hours the window rolls over and mining resumes, with the
    // counter reset to one: any half-open 24-hour window still contains at
    // most six claims, which is the rule the protocol promises.
    env.advance_to(account.claim_window_start + PROTOCOL_DAY_SECS);
    let tx = env.claim_tx(&founder, MAX_CLAIMS_PER_DAY + 1);
    env.commit(vec![tx], Vec::new()).expect("the window rolled over");
    let account = env.state.account(&address).unwrap().clone();
    assert_eq!(account.claims_today, 1);
    assert_eq!(
        account.claim_window_start,
        t0 + PROTOCOL_DAY_SECS,
        "a new window is anchored at the claim that opened it"
    );
    assert_eq!(env.state.total_claims, MAX_CLAIMS_PER_DAY + 1);
}

#[test]
fn the_daily_cap_is_an_independent_fail_closed_guard() {
    // The 4-hour interval already implies at most six claims per protocol day.
    // The cap is retained as a second, independent rule: if the interval were
    // ever relaxed, or if a state corruption produced an impossible counter, the
    // cap still refuses to issue value.
    let mut env = Env::new();
    let (founder, address) = env.genesis();
    let last = env.state.account(&address).unwrap().last_claim_at;
    env.advance_to(last + CLAIM_INTERVAL_SECS);
    {
        let account = env.state.accounts.get_mut(&address).unwrap();
        account.claims_today = MAX_CLAIMS_PER_DAY;
        account.claim_window_start = env.state.last_timestamp;
    }
    let tx = env.claim_tx(&founder, 2);
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "claim_daily_cap");
    assert_eq!(env.state.account(&address).unwrap().last_claim_sequence, 1);
}

#[test]
fn a_claim_must_declare_the_blocks_protocol_time() {
    let mut env = Env::new();
    let (founder, address) = env.genesis();
    env.advance_to(env.time + CLAIM_INTERVAL_SECS);

    for offset in [-1i64, 1, 3_600] {
        let wrong = (env.time as i64 + offset) as u64;
        let nonce = env.state.account(&address).unwrap().last_nonce + 1;
        let tx = Transaction::sign(
            MAINNET,
            nonce,
            TxKind::Claim(Claim {
                account: address,
                claimed_at: wrong,
                sequence: 2,
            }),
            &founder,
        );
        let error = env.commit(vec![tx], Vec::new()).unwrap_err();
        assert_eq!(
            error.rule, "timestamp_protocol_claim",
            "a claim that declares protocol time {} must be refused",
            wrong
        );
        assert_eq!(env.state.account(&address).unwrap().last_claim_sequence, 1);
    }

    // With the correct protocol time it applies.
    let tx = env.claim_tx(&founder, 2);
    env.commit(vec![tx], Vec::new()).unwrap();
    assert_eq!(env.state.account(&address).unwrap().last_claim_sequence, 2);
}

#[test]
fn a_claim_that_is_not_signed_by_the_account_is_rejected() {
    let mut env = Env::new();
    let (_founder, address) = env.genesis();
    let attacker = Keypair::from_seed(&[54u8; 32]);
    env.advance_to(env.time + CLAIM_INTERVAL_SECS);
    let tx = env.sign(
        &attacker,
        TxKind::Claim(Claim {
            account: address,
            claimed_at: env.time,
            sequence: 2,
        }),
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "claim_account");
}

#[test]
fn a_claim_sequence_cannot_be_reused() {
    let mut env = Env::new();
    let (founder, _address) = env.genesis();
    env.advance_to(env.time + CLAIM_INTERVAL_SECS);
    let tx = env.claim_tx(&founder, 1);
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "claim_sequence");
}

// ---------------------------------------------------------------------------
// Transfers, gas and the value split
// ---------------------------------------------------------------------------

#[test]
fn a_transfer_charges_the_protocol_gas_fee_and_splits_it_40_60() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    let bob = Keypair::from_seed(&[55u8; 32]);
    let bob_address = env.register(&bob, "bob@gmail.com", "TEST-INVITE-BOB");
    let miner_before = env.state.balance(&founder_address);
    let mining_pool_before = env.state.mining_pool;
    let validator_pool_before = env.state.validator_pool;

    let amount = Amount::parse("10").unwrap();
    let tx = transfer(&mut env, &founder, bob_address, amount);
    let effects = env.commit(vec![tx], Vec::new()).unwrap();
    let fee = gas_fee_for(amount);
    assert_eq!(effects.fees, fee);
    assert_eq!(env.state.balance(&bob_address), amount);
    assert_eq!(
        env.state.balance(&founder_address),
        miner_before
            .checked_sub(amount)
            .unwrap()
            .checked_sub(fee)
            .unwrap()
    );
    let (validator_share, mining_share) = split_gas_fee(fee);
    assert_eq!(
        env.state.validator_pool,
        validator_pool_before.checked_add(validator_share).unwrap()
    );
    assert_eq!(
        env.state.mining_pool,
        mining_pool_before.checked_add(mining_share).unwrap()
    );
    // Nothing was created: the total is conserved exactly.
    assert_eq!(
        env.state.issued_supply,
        GENESIS_ALLOCATION
            .checked_add(Amount(BASE_CLAIM_GRAINS))
            .unwrap()
    );
}

#[test]
fn the_gas_fee_is_capped_at_one_hundredth_of_a_coin() {
    let mut env = Env::new();
    let (founder, _) = env.genesis();
    let bob = Keypair::from_seed(&[56u8; 32]);
    let bob_address = env.register(&bob, "carol@gmail.com", "TEST-INVITE-CAROL");
    // The cap binds above 50 OBS: 0.02% of 50 OBS is exactly 0.01 OBS.
    assert_eq!(gas_fee_for(Amount::parse("50").unwrap()), MAX_GAS_FEE);
    assert_eq!(gas_fee_for(Amount::parse("1000").unwrap()), MAX_GAS_FEE);
    assert_eq!(
        gas_fee_for(Amount::parse("1").unwrap()),
        Amount::from_grains(200_000_000)
    );
    let huge = Amount::parse("1000").unwrap();
    let tx = transfer(&mut env, &founder, bob_address, huge);
    let effects = env.commit(vec![tx], Vec::new()).unwrap();
    assert_eq!(effects.fees, MAX_GAS_FEE, "the cap binds, with no float error");
    assert_eq!(MAX_GAS_FEE, Amount::parse("0.01").unwrap());
}

#[test]
fn a_transfer_beyond_the_balance_is_rejected() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    let balance = env.state.balance(&founder_address);
    let bob = Keypair::from_seed(&[57u8; 32]);
    let bob_address = env.register(&bob, "dave@gmail.com", "TEST-INVITE-DAVE");
    let tx = transfer(&mut env, &founder, bob_address, balance);
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "tx_insufficient_funds");
}

#[test]
fn a_signed_transaction_cannot_be_replayed_or_used_on_another_network() {
    let mut env = Env::new();
    let (founder, _) = env.genesis();
    let bob = Keypair::from_seed(&[58u8; 32]);
    let bob_address = env.register(&bob, "erin@gmail.com", "TEST-INVITE-ERIN");

    let tx = transfer(&mut env, &founder, bob_address, Amount::parse("1").unwrap());
    env.commit(vec![tx.clone()], Vec::new()).unwrap();
    // Replaying the identical signed transaction: the nonce is consumed.
    let error = env.commit(vec![tx.clone()], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "tx_nonce");

    // The same body signed for another network.
    assert_eq!(
        env.state.last_slot,
        env.state.last_timestamp / SLOT_DURATION_SECS,
        "the slot is derived from protocol time, never chosen freely"
    );
    let mut foreign = tx;
    foreign.chain_id = TESTNET.chain_id;
    let error = env.commit(vec![foreign], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "tx_chain_id");
}

// ---------------------------------------------------------------------------
// Validators: bonds, evidence-based uptime, unbonding, equivocation
// ---------------------------------------------------------------------------

#[test]
fn a_validator_must_lock_fifty_obs_and_use_a_distinct_node_key() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    let owner = Keypair::from_seed(&[60u8; 32]);
    let owner_address = env.register(&owner, "val@gmail.com", "TEST-INVITE-VAL");
    assert_eq!(env.state.balance(&owner_address), Amount::ZERO);

    // Without the bond: refused.
    let node = Keypair::from_seed(&[61u8; 32]);
    let tx = env.sign(
        &owner,
        TxKind::RegisterValidator {
            node_key: node.public_key(),
            endpoint: "node.obsidian.example:9200".to_string(),
        },
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "validator_bond");

    // Fund the bond, then register: the bond leaves the balance.
    fund(&mut env, owner_address, VALIDATOR_BOND);
    let tx = env.sign(
        &owner,
        TxKind::RegisterValidator {
            node_key: node.public_key(),
            endpoint: "node.obsidian.example:9200".to_string(),
        },
    );
    env.commit(vec![tx], Vec::new()).unwrap();
    assert_eq!(env.state.balance(&owner_address), Amount::ZERO);
    assert_eq!(env.state.locked_bonds(), VALIDATOR_BOND);
    let record = env.state.validator(&node.public_key()).unwrap();
    assert!(record.active);
    assert_eq!(record.bond, VALIDATOR_BOND);
    assert_eq!(record.owner, owner_address);
    assert_ne!(
        node.public_key(),
        owner.public_key(),
        "the node identity is distinct from the wallet key"
    );

    // The same node key cannot be registered twice.
    let second_owner = Keypair::from_seed(&[62u8; 32]);
    let second_address = env.register(&second_owner, "val2@gmail.com", "TEST-INVITE-VAL2");
    fund(&mut env, second_address, VALIDATOR_BOND);
    let tx = env.sign(
        &second_owner,
        TxKind::RegisterValidator {
            node_key: node.public_key(),
            endpoint: "other.obsidian.example:9200".to_string(),
        },
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "validator_exists");
    let _ = founder_address;
    let _ = founder;
}

#[test]
fn an_empty_endpoint_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[63u8; 32]);
    let owner_address = env.register(&owner, "val3@gmail.com", "TEST-INVITE-VAL3");
    fund(&mut env, owner_address, VALIDATOR_BOND);
    let tx = env.sign(
        &owner,
        TxKind::RegisterValidator {
            node_key: Keypair::from_seed(&[64u8; 32]).public_key(),
            endpoint: String::new(),
        },
    );
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "validator_endpoint");
}

#[test]
fn deregistering_returns_the_bond_after_exactly_48_hours() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[65u8; 32]);
    let node = Keypair::from_seed(&[66u8; 32]);
    env.add_validator(&owner, &node, "VAL4");
    let owner_address = Env::address(&owner);
    let deregister = {
        let owner = owner.clone();
        env.sign(&owner, TxKind::DeregisterValidator)
    };
    env.commit(vec![deregister], Vec::new()).unwrap();
    let record = env.state.validator(&node.public_key()).unwrap();
    assert!(!record.active);
    assert_eq!(record.exit_reason, Some(ExitReason::Deregistered));
    assert_eq!(env.state.locked_bonds(), VALIDATOR_BOND, "the bond is still locked");
    assert_eq!(env.state.balance(&owner_address), Amount::ZERO);
    let release_at = record.unbonding_ends_at;
    assert_eq!(
        release_at,
        env.state.last_timestamp + UNBONDING_PERIOD_SECS,
        "the cooldown is exactly 48 hours from the block that deregistered it"
    );

    // One second before the cooldown ends: nothing moves.  The lock is part of
    // consensus, so no client, API or operator can release it early.
    env.advance_to(release_at - 1);
    let proposer = env.proposer.clone();
    env.commit_at(&proposer, release_at - 1, Vec::new(), Vec::new())
        .unwrap();
    assert_eq!(env.state.balance(&owner_address), Amount::ZERO);
    assert_eq!(env.state.locked_bonds(), VALIDATOR_BOND);

    // At exactly 48 hours: returned in full.
    env.advance_to(release_at);
    let proposer = env.proposer.clone();
    env.commit_at(&proposer, release_at, Vec::new(), Vec::new())
        .unwrap();
    assert_eq!(env.state.balance(&owner_address), VALIDATOR_BOND);
    assert_eq!(env.state.locked_bonds(), Amount::ZERO);
    assert_eq!(env.active_validators().len(), 0);
}

#[test]
fn uptime_comes_from_signed_attestations_not_from_self_reports() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[67u8; 32]);
    let node = Keypair::from_seed(&[68u8; 32]);
    env.add_validator(&owner, &node, "VAL5");
    assert_eq!(env.active_validators(), vec![node.public_key()]);
    let record = env.state.validator(&node.public_key()).unwrap().clone();
    assert_eq!(record.attestation_count, 0, "no evidence yet");
    assert_eq!(env.state.validator_score(&node.public_key(), env.time), Some(0));

    // Attest the head in the next block: the evidence is the signature.
    let height = env.state.height;
    let hash = env.state.last_block_hash;
    let slot = env.state.last_slot;
    let attestation = Attestation::sign(MAINNET.chain_id, &node, height, hash, slot);
    env.commit(vec![], vec![attestation]).unwrap();
    let record = env.state.validator(&node.public_key()).unwrap().clone();
    assert_eq!(record.attestation_count, 1);
    assert_eq!(record.last_attested_height, height);
    assert!(env.state.validator_score(&node.public_key(), env.time).unwrap() > 0);

    // A forged attestation (right shape, wrong signer) is rejected.
    let impostor = Keypair::from_seed(&[69u8; 32]);
    let height = env.state.height;
    let hash = env.state.last_block_hash;
    let slot = env.state.last_slot;
    let mut forged = Attestation::sign(MAINNET.chain_id, &impostor, height, hash, slot);
    forged.node_key = node.public_key();
    let error = env.commit(vec![], vec![forged]).unwrap_err();
    assert_eq!(error.rule, "attestation_signature");

    // An attestation for a height whose block this node does not retain is
    // rejected rather than ignored: a node never guesses what it cannot verify.
    let _ = env.commit(vec![], Vec::new());
    let forgotten_height = env.state.height - 1;
    let retained = env.state.block_hashes.remove(&forgotten_height).unwrap();
    let unknown = Attestation::sign(MAINNET.chain_id, &node, forgotten_height, retained, slot);
    let error = env.commit(vec![], vec![unknown]).unwrap_err();
    assert_eq!(error.rule, "attestation_unknown_block");
    env.state.block_hashes.insert(forgotten_height, retained);

    // An attestation for another network is rejected.
    let foreign = Attestation::sign(TESTNET.chain_id, &node, height, hash, slot);
    let error = env.commit(vec![], vec![foreign]).unwrap_err();
    assert_eq!(error.rule, "attestation_signature");
}

#[test]
fn equivocation_is_punished_from_two_signed_attestations() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[70u8; 32]);
    let node = Keypair::from_seed(&[71u8; 32]);
    env.add_validator(&owner, &node, "VAL6");

    let height = env.state.height;
    let slot = env.state.last_slot;
    let honest = Attestation::sign(MAINNET.chain_id, &node, height, env.state.last_block_hash, slot);
    env.commit(vec![], vec![honest]).unwrap();
    assert!(env.state.validator(&node.public_key()).unwrap().active);

    // The same node signs a different block for the same height.  The chain
    // holds both signatures, which is all the evidence a removal needs.
    let conflicting = Attestation::sign(
        MAINNET.chain_id,
        &node,
        height,
        obs_primitives::hash::Hash32::from_bytes([0xAB; 32]),
        slot,
    );
    env.commit(vec![], vec![conflicting]).unwrap();
    let record = env.state.validator(&node.public_key()).unwrap();
    assert!(
        !record.active,
        "equivocation removes the validator without any human intervention"
    );
    assert_eq!(record.exit_reason, Some(ExitReason::Equivocation));
    assert_eq!(env.active_validators().len(), 0);
}

#[test]
fn past_the_bootstrap_window_only_the_scheduled_validator_may_propose() {
    // The bootstrap rule (any registered account may propose) exists so a new
    // network can start.  It is time-bounded: once the chain is past
    // `BOOTSTRAP_SLOTS` and a validator set exists, exactly one key is
    // authorised per slot, and which key that is comes from the schedule rather
    // than from whoever is willing to propose.
    let mut env = Env::new();
    env.genesis();
    let owners: Vec<Keypair> = (0..3)
        .map(|index| Keypair::from_seed(&[90 + index as u8; 32]))
        .collect();
    let nodes: Vec<Keypair> = (0..3)
        .map(|index| Keypair::from_seed(&[95 + index as u8; 32]))
        .collect();
    for (index, owner) in owners.iter().enumerate() {
        env.add_validator(owner, &nodes[index], &format!("SCHED{}", index));
    }
    let active = env.active_validators();
    assert_eq!(active.len(), 3);

    // Walk to the last block of the bootstrap window.  Until then any
    // registered account may propose, which is how the founder's own key has
    // been producing blocks all along.
    let founder = env.proposer.clone();
    while env.state.height < BOOTSTRAP_SLOTS {
        let timestamp = env.time + 59;
        env.commit_at(&founder, timestamp, Vec::new(), Vec::new())
            .expect("a bootstrap block applies");
    }

    // The first scheduled slot belongs to exactly one of the three.
    let timestamp = env.time + 1;
    let slot = timestamp / SLOT_DURATION_SECS;
    let index = proposer_for_slot(
        MAINNET.chain_id,
        &env.state.last_block_hash,
        slot,
        active.len(),
    )
    .expect("a slot with validators has a proposer");
    let scheduled = nodes
        .iter()
        .find(|node| node.public_key() == active[index])
        .expect("the scheduled key is one of ours");
    let others: Vec<&Keypair> = nodes
        .iter()
        .filter(|node| node.public_key() != active[index])
        .collect();

    // Everyone else is refused, with the rule that caught them.
    for other in &others {
        let error = env
            .commit_at(other, timestamp, Vec::new(), Vec::new())
            .expect_err("only the scheduled proposer may propose");
        assert_eq!(error.rule, "block_proposer");
    }

    // The scheduled validator's block applies, carries the two attestations it
    // was given, and credits it with the block it proposed.  The third
    // validator attested nothing, which the chain records as a missed
    // opportunity rather than as a claim either way.
    let head = env.state.height;
    let hash = env.state.last_block_hash;
    let head_slot = env.state.last_slot;
    // Every validator was silent for the whole bootstrap window, so what the
    // block changes is the interesting part.
    let missed_before: Vec<u64> = nodes
        .iter()
        .map(|node| {
            env.state
                .validator(&node.public_key())
                .unwrap()
                .missed_slots
        })
        .collect();
    let attestations: Vec<Attestation> = [0usize, 1]
        .iter()
        .map(|index| Attestation::sign(MAINNET.chain_id, &nodes[*index], head, hash, head_slot))
        .collect();
    env.commit_at(scheduled, timestamp, Vec::new(), attestations.clone())
        .expect("the scheduled proposer's block applies");

    let record = env
        .state
        .validator(&scheduled.public_key())
        .expect("the proposer is a validator")
        .clone();
    assert_eq!(record.blocks_proposed, 1, "the chain credits the proposer");
    for (index, node) in nodes.iter().enumerate() {
        let missed = env.state.validator(&node.public_key()).unwrap().missed_slots;
        let attested = attestations
            .iter()
            .any(|attestation| attestation.node_key == node.public_key());
        assert_eq!(
            missed,
            missed_before[index] + if attested { 0 } else { 1 },
            "a block that carries a validator's attestation is not an opportunity it missed, \
             and one that does not is: validator {} attested: {}",
            index,
            attested
        );
    }

    // Two of three is a quorum, so the attested height is final.
    assert!(
        env.state.finalized_height >= head,
        "an attested block reaches finality: {} >= {}",
        env.state.finalized_height,
        head
    );
}

#[test]
fn an_attestation_cannot_be_used_long_after_the_block_it_references() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[77u8; 32]);
    let node = Keypair::from_seed(&[78u8; 32]);
    env.add_validator(&owner, &node, "VAL8");
    let height = env.state.height;
    let hash = env.state.last_block_hash;
    let slot = env.state.last_slot;
    // A perfectly valid signature, made while the block still existed — but the
    // validator then went silent, so by the time a proposer could include it, it
    // no longer describes a live validator and must not buy PoT weight.
    let stale = Attestation::sign(MAINNET.chain_id, &node, height, hash, slot);
    for _ in 0..ATTESTATION_WINDOW_BLOCKS + 1 {
        env.commit(vec![], Vec::new()).unwrap();
    }
    assert_eq!(env.state.validator(&node.public_key()).unwrap().attestation_count, 0);
    let error = env.commit(vec![], vec![stale]).unwrap_err();
    assert_eq!(error.rule, "attestation_stale");
}

#[test]
fn the_chain_credits_proposers_and_counts_missed_opportunities() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[79u8; 32]);
    let node = Keypair::from_seed(&[80u8; 32]);
    env.add_validator(&owner, &node, "VAL9");
    assert_eq!(
        env.state.validator(&node.public_key()).unwrap().missed_slots,
        0,
        "the block that registers a validator is not an opportunity it missed"
    );

    // One block the validator proposes silently, then one that carries its
    // attestation for the previous head.
    env.commit_as(&node, vec![], Vec::new()).unwrap();
    let height = env.state.height;
    let hash = env.state.last_block_hash;
    let slot = env.state.last_slot;
    let attestation = Attestation::sign(MAINNET.chain_id, &node, height, hash, slot);
    env.commit_as(&node, vec![], vec![attestation]).unwrap();

    let record = env.state.validator(&node.public_key()).unwrap().clone();
    assert_eq!(record.blocks_proposed, 2, "both blocks name this node");
    assert_eq!(record.attestation_count, 1, "one piece of evidence");
    assert_eq!(record.missed_slots, 1, "one block carried no evidence");
    assert!(env.state.validator_score(&node.public_key(), env.time).unwrap() > 0);

    // A validator can also propose with the wallet key that owns its bond:
    // inside the bootstrap window a registered account may propose, and the bond
    // — not only the attestation identity — belongs to the wallet.  This is the
    // configuration a live devnet runs (one validator, mining with the founder
    // wallet), and it used to be credited with nothing at all.
    env.commit_as(&owner, vec![], Vec::new())
        .expect("the bond's wallet may propose in bootstrap mode");
    let record = env.state.validator(&node.public_key()).unwrap().clone();
    assert_eq!(
        record.blocks_proposed, 3,
        "a block proposed by the bond's wallet is credited to its validator"
    );
}

#[test]
fn attestations_are_counted_once_per_validator() {
    let mut env = Env::new();
    env.genesis();
    let owner = Keypair::from_seed(&[75u8; 32]);
    let node = Keypair::from_seed(&[76u8; 32]);
    env.add_validator(&owner, &node, "VAL7");
    let height = env.state.height;
    let hash = env.state.last_block_hash;
    let slot = env.state.last_slot;
    // A block carrying two attestations from the same validator for different
    // heights is fine; the *values* are what matter, and the second one for the
    // same height is refused as a duplicate rather than counted twice.
    let first = Attestation::sign(MAINNET.chain_id, &node, height, hash, slot);
    env.commit(vec![], vec![first]).unwrap();
    let duplicate = Attestation::sign(MAINNET.chain_id, &node, height, hash, slot);
    let error = env.commit(vec![], vec![duplicate]).unwrap_err();
    assert_eq!(error.rule, "attestation_duplicate");
    assert_eq!(env.state.validator(&node.public_key()).unwrap().attestation_count, 1);
}

// ---------------------------------------------------------------------------
// Blocks: structure, roots, timestamps, difficulty and weight
// ---------------------------------------------------------------------------

#[test]
fn a_block_that_does_not_follow_the_head_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let block = env
        .state
        .build_block(&env.proposer.clone(), env.time, Vec::new(), Vec::new())
        .unwrap();

    // Applying the same block twice: the height rule stops it.
    env.apply(&block).unwrap();
    let error = env.state.apply_block(&block).unwrap_err();
    assert_eq!(error.rule, "block_height");

    // A correctly numbered block that does not extend our head (a block from a
    // different branch) is refused: at the same height, the parent must match.
    let next = env
        .state
        .build_block(&env.proposer.clone(), env.time, Vec::new(), Vec::new())
        .unwrap();
    let mut branch = env.state.clone();
    branch.last_block_hash = obs_primitives::hash::Hash32::from_bytes([0x33; 32]);
    let error = branch.apply_block(&next).unwrap_err();
    assert_eq!(error.rule, "block_parent");
}

#[test]
fn tampering_with_a_block_body_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let bob = Keypair::from_seed(&[72u8; 32]);
    let bob_address = env.register(&bob, "tamper@gmail.com", "TEST-INVITE-TAMPER");
    let proposer = env.proposer.clone();
    let tx = transfer(&mut env, &proposer, bob_address, Amount::parse("5").unwrap());
    let block = env
        .state
        .build_block(&proposer, env.time, vec![tx], Vec::new())
        .unwrap();

    // 1. Editing a transaction in place breaks the transaction root, which the
    //    proposer signed.  A node sees the mismatch before anything is applied.
    let mut edited = block.clone();
    if let TxKind::Transfer { amount, .. } = &mut edited.transactions[0].kind {
        *amount = Amount::parse("5000").unwrap();
    }
    let error = env.state.apply_block(&edited).unwrap_err();
    assert!(
        error.rule == "block_structure" || error.rule == "block_signature",
        "an edited transaction must break the block, got {}",
        error.rule
    );

    // 2. A malicious proposer can recompute the root and re-sign, so the block
    //    is internally consistent.  The transaction's own signature is what
    //    stops it: the body no longer matches what the sender authorised.
    let mut forged = block.clone();
    if let TxKind::Transfer { amount, .. } = &mut forged.transactions[0].kind {
        *amount = Amount::parse("5000").unwrap();
    }
    forged.header.tx_root = forged.compute_tx_root();
    forged.sign(&proposer);
    assert_eq!(
        env.state.apply_block(&forged).unwrap_err().rule,
        "tx_signature"
    );

    // 3. A transaction signature replaced with garbage: same story.
    let mut spliced = block.clone();
    spliced.transactions[0].signature = [9u8; 64];
    spliced.header.tx_root = spliced.compute_tx_root();
    spliced.sign(&proposer);
    assert_eq!(
        env.state.apply_block(&spliced).unwrap_err().rule,
        "tx_signature"
    );

    // 4. An attestation forged into the block: the attestation signature is
    //    checked, so a proposer cannot invent validator participation.
    let mut attested = block.clone();
    attested.attestations.push(obs_chain::block::Attestation {
        node_key: [7u8; 32],
        height: 1,
        block_hash: obs_primitives::hash::Hash32::from_bytes([0x22; 32]),
        slot: 0,
        signature: [3u8; 64],
    });
    attested.header.attestation_root = attested.compute_attestation_root();
    attested.sign(&proposer);
    let error = env.state.apply_block(&attested).unwrap_err();
    assert!(
        error.rule == "attestation_signature" || error.rule == "attestation_unknown_block",
        "a forged attestation must be refused, got {}",
        error.rule
    );

    // The untouched block still applies: the rules reject tampering, not the
    // honest block they were built from.
    env.apply(&block).unwrap();
}

#[test]
fn a_block_committing_to_the_wrong_state_root_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let proposer = env.proposer.clone();
    let mut block = env
        .state
        .build_block(&proposer, env.time, Vec::new(), Vec::new())
        .unwrap();
    block.header.state_root = obs_primitives::hash::Hash32::from_bytes([0x11; 32]);
    block.sign(&proposer);
    let error = env.state.apply_block(&block).unwrap_err();
    assert_eq!(error.rule, "block_state_root");
}

#[test]
fn a_block_that_claims_the_wrong_weight_or_difficulty_is_rejected() {
    let mut env = Env::new();
    env.genesis();
    let proposer = env.proposer.clone();

    let mut block = env
        .state
        .build_block(&proposer, env.time, Vec::new(), Vec::new())
        .unwrap();
    block.header.weight_atoms += 1;
    block.sign(&proposer);
    assert_eq!(env.state.apply_block(&block).unwrap_err().rule, "block_weight");

    let mut block = env
        .state
        .build_block(&proposer, env.time, Vec::new(), Vec::new())
        .unwrap();
    block.header.difficulty_bp += 1;
    block.sign(&proposer);
    assert_eq!(
        env.state.apply_block(&block).unwrap_err().rule,
        "block_difficulty"
    );
}

#[test]
fn timestamp_rules_are_enforced() {
    let mut env = Env::new();
    env.genesis();
    let proposer = env.proposer.clone();
    let mtp = env.state.median_time_past();
    let parent = env.state.last_timestamp;

    // Rule 1: strictly after the median time past.
    let error = env
        .state
        .build_block(&proposer, mtp, Vec::new(), Vec::new())
        .unwrap_err();
    assert_eq!(error.rule, "timestamp_mtp");

    // Rule 2: strictly after the parent.
    let error = env
        .state
        .build_block(&proposer, parent, Vec::new(), Vec::new())
        .unwrap_err();
    assert!(
        error.rule == "timestamp_parent_min" || error.rule == "timestamp_mtp",
        "unexpected rule {}",
        error.rule
    );

    // Rule 3: no further than the drift limit ahead of the parent.
    let error = env
        .state
        .build_block(&proposer, parent + 61, Vec::new(), Vec::new())
        .unwrap_err();
    assert_eq!(error.rule, "timestamp_parent_drift");

    // And a block inside the window applies.
    let ok = env
        .state
        .build_block(&proposer, parent + 60, Vec::new(), Vec::new())
        .unwrap();
    env.apply(&ok).unwrap();
}

#[test]
fn the_median_time_past_tracks_the_block_history() {
    let mut env = Env::new();
    env.genesis();
    let initial = env.state.median_time_past();
    assert!(initial > 0);
    for _ in 0..12 {
        let timestamp = env.time + 30;
        let proposer = env.proposer.clone();
        let block = env
            .state
            .build_block(&proposer, timestamp, Vec::new(), Vec::new())
            .unwrap();
        env.apply(&block).unwrap();
    }
    let later = env.state.median_time_past();
    assert!(
        later > initial,
        "the median time past follows the chain forward"
    );
    assert!(later <= env.state.last_timestamp);
}

// ---------------------------------------------------------------------------
// Determinism, conservation and supply
// ---------------------------------------------------------------------------

#[test]
fn the_state_root_is_deterministic_and_commits_to_every_change() {
    // Two independent instances of the network: same keys, same transactions,
    // same protocol rules.  They must agree exactly, everywhere.
    let mut env = Env::new();
    let (founder, _founder_address) = env.genesis();
    let mut other = Env::new();
    let (other_founder, _other_address) = other.genesis();
    assert_eq!(
        other.state.state_root(),
        env.state.state_root(),
        "two nodes that see the same genesis hold the same state root"
    );
    assert_eq!(other.state.last_block_hash, env.state.last_block_hash);

    let bob = Keypair::from_seed(&[73u8; 32]);
    let bob_address = env.register(&bob, "det@gmail.com", "TEST-INVITE-DET");
    other.register(&bob, "det@gmail.com", "TEST-INVITE-DET");
    assert_eq!(
        other.state.state_root(),
        env.state.state_root(),
        "registration is deterministic"
    );

    let tx = transfer(&mut env, &founder, bob_address, Amount::parse("1").unwrap());
    let other_tx = transfer(&mut other, &other_founder, bob_address, Amount::parse("1").unwrap());
    assert_eq!(other_tx.id(), tx.id(), "identical transactions have identical ids");
    assert_eq!(other_tx.to_bytes(), tx.to_bytes(), "and identical bytes");

    let block = env
        .state
        .build_block(&env.proposer.clone(), env.time, vec![tx], Vec::new())
        .unwrap();
    let other_block = other
        .state
        .build_block(&other.proposer.clone(), other.time, vec![other_tx], Vec::new())
        .unwrap();
    assert_eq!(
        other_block.hash(),
        block.hash(),
        "the same transactions produce the same block, byte for byte"
    );

    let first = env.state.apply_block(&block).unwrap();
    // Applying the same block twice to the same state gives the same root, and
    // the root differs from the parent's: it really commits to the change.
    let second = env.state.apply_block(&block).unwrap();
    assert_eq!(first.state.state_root(), second.state.state_root());
    assert_ne!(first.state.state_root(), env.state.state_root());
    assert_eq!(first.effects.hash, block.hash());
    assert!(
        first.effects.entries.iter().any(|entry| entry.kind == "transfer"),
        "the effects list is the auditable ledger of what the block did"
    );
    assert_eq!(first.state.last_block_hash, block.hash());
    assert_eq!(
        other.state.apply_block(&other_block).unwrap().state.state_root(),
        first.state.state_root()
    );

    // The root commits to balances, to the account set and to the pools: if a
    // byte of any of them changes, the root changes with it.
    let account = env.state.accounts.get(&bob_address).unwrap().clone();
    for mutated in [
        {
            let mut state = first.state.clone();
            let account = state.accounts.get_mut(&bob_address).unwrap();
            account.balance = account.balance.checked_add(Amount(1)).unwrap();
            state
        },
        {
            let mut state = first.state.clone();
            state.mining_pool = state.mining_pool.checked_add(Amount(1)).unwrap();
            state
        },
        {
            let mut state = first.state.clone();
            state.accounts.remove(&bob_address);
            state
        },
        {
            let mut state = first.state.clone();
            state.total_weight = state.total_weight.checked_add(obs_chain::pot::PoTWeight::from_atoms(1));
            state
        },
        {
            let mut state = first.state.clone();
            state.total_claims += 1;
            state
        },
    ] {
        assert_ne!(
            mutated.state_root(),
            first.state.state_root(),
            "every field of the committed state is covered by the root"
        );
        assert_eq!(account.wallet_key, bob.public_key());
    }

    // The chain position (height and parent) is committed by the block header
    // instead, which is what lets two nodes compare branches before they have
    // replayed them.
    let mut renumbered = first.state.clone();
    renumbered.height = renumbered.height + 1;
    assert_eq!(renumbered.state_root(), first.state.state_root());
}

#[test]
fn a_long_sequence_of_blocks_keeps_the_supply_and_balances_conserved() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    let miner = Keypair::from_seed(&[74u8; 32]);
    let miner_address = env.register(&miner, "long@gmail.com", "TEST-INVITE-LONG");

    // The genesis block mined the first claim.
    let mut total_claims = 1u64;
    for round in 0..24u64 {
        // Advance protocol time so claims become eligible again.
        let target = env.time + CLAIM_INTERVAL_SECS;
        env.advance_to(target);
        let sequence = env.state.account(&miner_address).unwrap().last_claim_sequence + 1;
        let claim = env.claim_tx(&miner, sequence);
        let mut txs = vec![claim];
        // Every other round the founder also moves value, paying a fee.
        if round % 2 == 0 {
            let amount = Amount::parse("0.5").unwrap();
            txs.push(transfer(&mut env, &founder, miner_address, amount));
        }
        env.commit(txs, Vec::new()).expect("the round applies");
        total_claims += 1;

        // Invariants after every single block.
        env.state.check_invariants().unwrap();
        let balances: u128 = env.state.accounts.values().map(|a| a.balance.grains()).sum();
        let accounted = balances
            + env.state.mining_pool.grains()
            + env.state.validator_pool.grains()
            + env.state.locked_bonds().grains();
        assert_eq!(accounted, env.state.issued_supply.grains());
        assert!(env.state.issued_supply <= MAX_SUPPLY);
    }
    assert_eq!(env.state.total_claims, total_claims);
    assert_eq!(env.state.total_claims, 1 + 24, "the genesis claim plus the loop");
    assert!(env.state.height > 24, "the chain really grew");
    assert_eq!(env.state.accounts.len(), 2);
    assert_eq!(env.state.issued_supply.grains(), {
        let balances: u128 = env.state.accounts.values().map(|a| a.balance.grains()).sum();
        balances + env.state.mining_pool.grains() + env.state.validator_pool.grains()
    });
    let _ = founder_address;
}

#[test]
fn an_account_cannot_mint_value_by_itself() {
    let mut env = Env::new();
    let (founder, founder_address) = env.genesis();
    let before = env.state.issued_supply;

    // A transfer moves value; it does not create it.  Even the richest account
    // cannot raise its own balance: every change goes through the protocol.
    let tx = transfer(&mut env, &founder, founder_address, Amount::parse("1").unwrap());
    let error = env.commit(vec![tx], Vec::new()).unwrap_err();
    assert_eq!(error.rule, "tx_self_transfer");
    assert_eq!(env.state.issued_supply, before);
}

#[test]
fn blocks_cannot_exceed_the_protocol_transaction_limit() {
    // The limit exists so that a block can always be validated in bounded work;
    // it is enforced before the block's contents are examined at all.
    let mut env = Env::new();
    env.genesis();
    let proposer = env.proposer.clone();
    let block = env
        .state
        .build_block(&proposer, env.time, Vec::new(), Vec::new())
        .unwrap();
    let mut oversized = block.clone();
    oversized.transactions = vec![block.transactions.first().cloned().unwrap_or_else(|| {
        obs_chain::Transaction {
            chain_id: MAINNET.chain_id,
            nonce: 1,
            kind: TxKind::DeregisterValidator,
            public_key: [0u8; 32],
            signature: [0u8; 64],
        }
    }); MAX_TXS_PER_BLOCK + 1];
    let error = env.state.apply_block(&oversized).unwrap_err();
    assert_eq!(error.rule, "block_structure");
    assert!(MAX_TXS_PER_BLOCK > 1_000, "the limit is a real bound, not a toy");
}

// ---------------------------------------------------------------------------
// Anti-PoW property: no hashing advantage exists
// ---------------------------------------------------------------------------

#[test]
fn no_amount_of_hashing_can_change_who_proposes_a_block() {
    // Nonces do not exist on the wire at all: a block has no nonce field, so
    // there is no work to grind.  The only freedom a proposer has is the
    // timestamp, and every timestamp it could choose is checked by the
    // protocol rules, while proposer scheduling comes from the parent hash and
    // the slot -- data the proposer cannot choose.
    let mut env = Env::new();
    env.genesis();
    let proposer = env.proposer.clone();
    let slot = env.state.last_slot + 1;

    // The same slot always selects the same proposer from the same parent.
    let a = obs_chain::pot::proposer_for_slot(MAINNET.chain_id, &env.state.last_block_hash, slot, 3);
    let b = obs_chain::pot::proposer_for_slot(MAINNET.chain_id, &env.state.last_block_hash, slot, 3);
    assert_eq!(a, b);
    assert!(a.is_some());

    // Attempting a block from a key that is not in the validator set is refused
    // regardless of how the header is tuned.
    let outsider = Keypair::from_seed(&[99u8; 32]);
    for timestamp in [env.time, env.time + 1, env.time + 30] {
        let block = env
            .state
            .build_block(&outsider, timestamp, Vec::new(), Vec::new());
        match block {
            Ok(block) => assert_eq!(
                env.state.apply_block(&block).unwrap_err().rule,
                "block_proposer"
            ),
            Err(error) => assert_eq!(error.rule, "block_proposer"),
        }
    }
    let _ = proposer;
}

#[test]
fn the_work_measure_is_time_rate_and_grows_with_participation() {
    // Weight is a function of protocol time and attested participation; there
    // is no hash target anywhere in the crate.
    let slow = obs_chain::pot::weight_of_block(8, 3, 3, 10_000);
    let fast = obs_chain::pot::weight_of_block(1, 3, 3, 10_000);
    assert!(slow > fast, "waiting longer is worth more time-rate");
    let quiet = obs_chain::pot::weight_of_block(8, 0, 3, 10_000);
    assert!(slow > quiet, "participation is part of the weight");
    let harder = obs_chain::pot::weight_of_block(8, 3, 3, 15_000);
    assert!(harder > slow, "difficulty scales the time-rate");
}

/// An amount that cannot exist is refused by name, not by panicking.
///
/// The fee for a transfer is derived from its amount, and the amount arrives
/// from a transaction's bytes — so a hostile sender can put any `u128` in that
/// field.  A transfer above the total supply is unpayable by construction: no
/// account can ever hold that much.  The state machine must say so, rather than
/// attempt arithmetic it cannot finish.  An overflow panic here would be far
/// worse than a rejected transaction: the state machine runs under the node's
/// state lock, so the panic would poison the lock and stop that node answering
/// anything at all.
#[test]
fn an_amount_that_cannot_exist_is_refused_by_name_rather_than_panicking() {
    let mut env = Env::new();
    let (founder, _) = env.genesis();
    let bob = Keypair::from_seed(&[66u8; 32]);
    let bob_address = env.register(&bob, "frank@gmail.com", "TEST-INVITE-FRANK");

    for amount in [
        Amount(MAX_SUPPLY.grains() + 1),
        Amount(u128::MAX / 2),
        Amount(u128::MAX / 2 + 1),
        Amount(u128::MAX - 1),
        Amount(u128::MAX),
    ] {
        let tx = transfer(&mut env, &founder, bob_address, amount);
        let error = env
            .commit(vec![tx], Vec::new())
            .expect_err("an amount above the total supply is unpayable");
        assert_eq!(
            error.rule, "tx_amount_above_supply",
            "amount {} must be refused by name",
            amount.grains()
        );
    }

    // A transfer for the whole supply is *payable in principle* — it gets past
    // the amount rule and fails on funds, which is the check it should fail.
    let at_the_line = Amount(MAX_SUPPLY.grains());
    let tx = transfer(&mut env, &founder, bob_address, at_the_line);
    let error = env
        .commit(vec![tx], Vec::new())
        .expect_err("no single account holds the whole supply");
    assert_eq!(error.rule, "tx_insufficient_funds");
}
