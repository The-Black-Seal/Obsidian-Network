//! Pool behaviour against the real state machine.
//!
//! Every transaction here is really signed, really validated against a real
//! chain state, and the block templates the pool produces are really applied.

use obs_chain::chain::{gmail_commitment, invite_commitment, Claim, InviteAuthorization};
use obs_chain::params::{BASE_CLAIM_GRAINS, GENESIS_TIMESTAMP};
use obs_chain::state::{ChainState, GenesisConfig};
use obs_chain::{Transaction, TxKind};
use obs_crypto::ed25519::Keypair;
use obs_mempool::{Mempool, MempoolConfig, MempoolError};
use obs_primitives::address::Address;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION};
use obs_primitives::network::{MAINNET, TESTNET};

struct World {
    authority: Keypair,
    founder: Keypair,
    founder_address: Address,
    state: ChainState,
    time: u64,
    nonces: std::collections::BTreeMap<Address, u64>,
    recovered: u64,
}

impl World {
    fn new() -> World {
        let authority = Keypair::from_seed(&[1u8; 32]);
        let founder = Keypair::from_seed(&[30u8; 32]);
        let founder_address = Address::from_public_key(MAINNET, &founder.public_key());
        let config = GenesisConfig {
            network: MAINNET,
            registration_authority: authority.public_key(),
            timestamp: GENESIS_TIMESTAMP,
        };
        let state = ChainState::new(&config);
        let mut world = World {
            authority,
            founder,
            founder_address,
            state,
            time: GENESIS_TIMESTAMP + 1,
            nonces: std::collections::BTreeMap::new(),
            recovered: 0,
        };

        // The launch block: the founder registers and mines the genesis claim.
        let invite = InviteAuthorization::issue(
            MAINNET.chain_id,
            &world.authority,
            invite_commitment(MAINNET.chain_id, "TEST-INVITE-GENESIS"),
            gmail_commitment(
                MAINNET.chain_id,
                &obs_primitives::identity::canonical_gmail("founder@gmail.com").unwrap(),
            ),
            world.time,
            world.time + 86_400,
            None,
        );
        let register = world.sign(
            &world.founder.clone(),
            TxKind::Register {
                account: founder_address,
                wallet_key: world.founder.public_key(),
                gmail_commitment: gmail_commitment(
                    MAINNET.chain_id,
                    &obs_primitives::identity::canonical_gmail("founder@gmail.com").unwrap(),
                ),
                invite,
            },
        );
        let founder_key = world.founder.clone();
        let claim = world.sign(
            &founder_key,
            TxKind::Claim(Claim {
                account: founder_address,
                claimed_at: world.time,
                sequence: 1,
            }),
        );
        let timestamp = world.time;
        let founder_key = world.founder.clone();
        let block = world
            .state
            .build_block(&founder_key, timestamp, vec![register, claim], Vec::new())
            .expect("the launch block builds");
        world.state = world.state.apply_block(&block).unwrap().state;
        world.time = timestamp + 1;
        world
    }

    fn next_nonce(&mut self, key: &Keypair) -> u64 {
        let address = Address::from_public_key(MAINNET, &key.public_key());
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

    /// Registers an account with an invitation issued by the founder.
    fn register(&mut self, key: &Keypair, index: u8) -> Address {
        let address = Address::from_public_key(MAINNET, &key.public_key());
        let mut recovered = self.recovered;
        // The invitation is bound to the canonical Gmail identity, exactly as
        // the registration request must be.
        let canonical = obs_primitives::identity::canonical_gmail(&format!(
            "miner{}@gmail.com",
            index
        ))
        .unwrap();
        let invite = InviteAuthorization::issue(
            MAINNET.chain_id,
            &self.authority,
            invite_commitment(MAINNET.chain_id, &format!("TEST-INVITE-{}", index)),
            gmail_commitment(MAINNET.chain_id, &canonical),
            self.time,
            self.time + 86_400,
            Some(self.founder_address),
        );
        recovered += 1;
        self.recovered = recovered;
        let tx = self.sign(
            key,
            TxKind::Register {
                account: address,
                wallet_key: key.public_key(),
                gmail_commitment: gmail_commitment(MAINNET.chain_id, &canonical),
                invite,
            },
        );
        let founder = self.founder.clone();
        let timestamp = self.time;
        let block = self
            .state
            .build_block(&founder, timestamp, vec![tx], Vec::new())
            .expect("registration block builds");
        self.state = self.state.apply_block(&block).unwrap().state;
        self.time = timestamp + 1;
        address
    }

    fn transfer(&mut self, from: &Keypair, to: Address, amount: Amount) -> Transaction {
        let key = from.clone();
        self.sign(&key, TxKind::Transfer { to, amount })
    }

    fn balance(&self, address: &Address) -> Amount {
        self.state.balance(address)
    }
}

fn pool() -> Mempool {
    Mempool::new(MempoolConfig::default())
}

#[test]
fn the_pool_accepts_valid_transactions_and_rejects_invalid_ones() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = pool();

    // A valid transfer is accepted.
    let good = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    let id = mempool.insert(&world.state, good.clone(), world.time).unwrap();
    assert!(mempool.contains(&id));
    assert_eq!(mempool.len(), 1);
    // Re-inserting the same transaction is reported as a duplicate.
    match mempool.insert(&world.state, good.clone(), world.time) {
        Err(MempoolError::Duplicate(duplicate)) => assert_eq!(duplicate, id),
        other => panic!("expected a duplicate, got {:?}", other.is_ok()),
    }

    // A forged signature.
    let mut forged = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    forged.signature = [7u8; 64];
    match mempool.insert(&world.state, forged, world.time) {
        Err(MempoolError::Invalid(error)) => assert_eq!(error.rule, "tx_signature"),
        other => panic!("expected a signature rejection, got {:?}", other.is_ok()),
    }

    // A transaction for another network.
    let mut foreign = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    foreign.chain_id = TESTNET.chain_id;
    match mempool.insert(&world.state, foreign, world.time) {
        Err(MempoolError::Invalid(error)) => assert_eq!(error.rule, "tx_chain_id"),
        other => panic!("expected a chain-id rejection, got {:?}", other.is_ok()),
    }

    // A transaction that is ahead of the account's nonce cannot be queued until
    // the transactions it depends on are pooled.
    let ahead = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    let ahead_nonce = ahead.nonce;
    match mempool.insert(&world.state, ahead, world.time) {
        Err(MempoolError::NonceGap { expected, got }) => {
            // The pooled transaction covers `good.nonce`, so the next nonce the
            // pool could queue is the one after it.
            assert_eq!(expected, good.nonce + 1);
            assert_eq!(got, ahead_nonce);
            assert!(got > expected);
        }
        other => panic!("expected a nonce gap, got {:?}", other.is_ok()),
    }

    // A replayed nonce (the transaction already mined).
    let replayed = Transaction::sign(
        MAINNET,
        2,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("1").unwrap(),
        },
        &world.founder.clone(),
    );
    match mempool.insert(&world.state, replayed, world.time) {
        Err(MempoolError::Invalid(error)) => assert_eq!(error.rule, "tx_nonce"),
        other => panic!("expected a nonce rejection, got {:?}", other.is_ok()),
    }

    assert_eq!(mempool.len(), 1, "only the valid transaction is retained");
    assert_eq!(mempool.stats().transactions, 1);
    assert_eq!(mempool.stats().accounts, 1);
}

#[test]
fn a_block_template_contains_nonces_in_order_and_applies() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = pool();

    // Two queued transfers from the founder.
    let first = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    let second = world.transfer(&world.founder.clone(), bob_address, Amount::parse("2").unwrap());
    assert_eq!(second.nonce, first.nonce + 1);
    mempool.insert(&world.state, first.clone(), world.time).unwrap();
    mempool.insert(&world.state, second.clone(), world.time).unwrap();

    let template = mempool.select_for_block(&world.state, world.time, 100);
    assert_eq!(template.len(), 2);
    assert_eq!(template[0].nonce, first.nonce);
    assert_eq!(template[1].nonce, second.nonce);

    // The template really applies, and the state really changes.
    let founder = world.founder.clone();
    let block = world
        .state
        .build_block(&founder, world.time, template.clone(), Vec::new())
        .expect("the template builds");
    let before = world.balance(&bob_address);
    let applied = world.state.apply_block(&block).expect("the template applies");
    let moved = Amount::parse("3").unwrap();
    assert_eq!(applied.state.balance(&bob_address), before.checked_add(moved).unwrap());

    // Applying the block clears the mined transactions from the pool.
    let dropped = mempool.on_block_applied(&applied.state, &block);
    assert_eq!(dropped, 2);
    assert!(mempool.is_empty());
}

#[test]
fn queued_nonces_are_admitted_together_and_selected_in_order() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = pool();

    let first = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    let second = world.transfer(&world.founder.clone(), bob_address, Amount::parse("2").unwrap());

    // The *second* transaction cannot be queued on its own: its predecessor is
    // missing, so the pool refuses it rather than holding something that can
    // never be applied as a sequence.
    match mempool.insert(&world.state, second.clone(), world.time) {
        Err(MempoolError::NonceGap { expected, got }) => {
            assert_eq!(expected, second.nonce - 1);
            assert_eq!(got, second.nonce);
        }
        other => panic!("expected a nonce gap, got {:?}", other.is_ok()),
    }
    assert!(mempool.is_empty());

    // With its predecessor pooled, both queue and both are selected in order.
    mempool.insert(&world.state, first.clone(), world.time).unwrap();
    mempool.insert(&world.state, second.clone(), world.time).unwrap();
    let template = mempool.select_for_block(&world.state, world.time, 100);
    assert_eq!(template.len(), 2);
    assert_eq!(template[0].id(), first.id());
    assert_eq!(template[1].id(), second.id());

    // A third transaction that the account cannot pay for is refused, because
    // the whole queued sequence has to apply.
    let third = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1000000").unwrap());
    match mempool.insert(&world.state, third, world.time) {
        Err(MempoolError::Invalid(error)) => assert_eq!(error.rule, "tx_insufficient_funds"),
        other => panic!("expected an insufficient-funds rejection, got {:?}", other.is_ok()),
    }
}

#[test]
fn higher_fees_are_selected_first_and_template_order_is_independent_of_arrival() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let alice = Keypair::from_seed(&[42u8; 32]);
    let alice_address = world.register(&alice, 2);

    // Fund both accounts so that their transfers are valid.
    let founder = world.founder.clone();
    let to_bob = world.transfer(&founder, bob_address, Amount::parse("1000").unwrap());
    let to_alice = world.transfer(&founder, alice_address, Amount::parse("1000").unwrap());
    let block = world
        .state
        .build_block(&founder, world.time, vec![to_bob, to_alice], Vec::new())
        .unwrap();
    let funding = world.state.apply_block(&block).unwrap();
    world.state = funding.state;
    world.time += 60;

    // Bob pays the maximum fee, Alice the minimum of her two accounts.
    let big = world.transfer(&bob.clone(), world.founder_address, Amount::parse("100").unwrap());
    let small = world.transfer(&alice.clone(), world.founder_address, Amount::parse("1").unwrap());
    assert!(obs_chain::params::gas_fee_for(Amount::parse("100").unwrap())
        > obs_chain::params::gas_fee_for(Amount::parse("1").unwrap()));

    let mut forward = pool();
    forward.insert(&world.state, small.clone(), world.time).unwrap();
    forward.insert(&world.state, big.clone(), world.time).unwrap();
    let mut backward = pool();
    backward.insert(&world.state, big.clone(), world.time).unwrap();
    backward.insert(&world.state, small.clone(), world.time).unwrap();

    let template_forward = forward.select_for_block(&world.state, world.time, 100);
    let template_backward = backward.select_for_block(&world.state, world.time, 100);
    assert_eq!(
        template_forward.iter().map(|tx| tx.id()).collect::<Vec<_>>(),
        template_backward.iter().map(|tx| tx.id()).collect::<Vec<_>>(),
        "two nodes with the same pool build the same template"
    );
    assert_eq!(template_forward[0].id(), big.id(), "the higher fee comes first");

    // And the template applies.
    let block = world
        .state
        .build_block(&founder, world.time, template_forward, Vec::new())
        .unwrap();
    world.state.apply_block(&block).expect("template applies");
}

#[test]
fn a_same_nonce_replacement_needs_a_strictly_higher_fee() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = pool();

    // Two transactions for the same nonce: a small one and a large one.
    let nonce = world.next_nonce(&world.founder.clone());
    let small = Transaction::sign(
        MAINNET,
        nonce,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("1").unwrap(),
        },
        &world.founder.clone(),
    );
    let big = Transaction::sign(
        MAINNET,
        nonce,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("10").unwrap(),
        },
        &world.founder.clone(),
    );
    assert!(obs_chain::params::gas_fee_for(Amount::parse("10").unwrap())
        > obs_chain::params::gas_fee_for(Amount::parse("1").unwrap()));

    mempool.insert(&world.state, small.clone(), world.time).unwrap();
    // The cheaper one cannot displace the pooled one.
    let cheaper = Transaction::sign(
        MAINNET,
        nonce,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("0.1").unwrap(),
        },
        &world.founder.clone(),
    );
    match mempool.insert(&world.state, cheaper, world.time) {
        Err(MempoolError::NonceConflict { nonce: conflicted }) => assert_eq!(conflicted, nonce),
        other => panic!("expected a nonce conflict, got {:?}", other.is_ok()),
    }
    assert!(mempool.contains(&small.id()));

    // A strictly better fee replaces it.
    mempool.insert(&world.state, big.clone(), world.time).unwrap();
    assert!(!mempool.contains(&small.id()));
    assert!(mempool.contains(&big.id()));
    assert_eq!(mempool.len(), 1);
}

#[test]
fn the_pool_is_bounded_per_account_and_in_total() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);

    // Per-account limit.
    let mut small_pool = Mempool::new(MempoolConfig {
        max_per_account: 2,
        ..MempoolConfig::default()
    });
    for index in 0..2u64 {
        let tx = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
        small_pool.insert(&world.state, tx, world.time).unwrap();
        let _ = index;
    }
    let third = Transaction::sign(
        MAINNET,
        world.next_nonce(&world.founder.clone()),
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("1").unwrap(),
        },
        &world.founder.clone(),
    );
    assert_eq!(third.nonce, 5, "the third queued nonce follows the two pooled ones");
    match small_pool.insert(&world.state, third, world.time) {
        Err(MempoolError::AccountFull { address, limit }) => {
            assert_eq!(address, world.founder_address);
            assert_eq!(limit, 2);
        }
        other => panic!("expected the account limit, got {:?}", other.is_ok()),
    }

    // Total limit: the cheapest entry is evicted for a better-paying one.
    let mut tiny = Mempool::new(MempoolConfig {
        max_transactions: 1,
        ..MempoolConfig::default()
    });
    let next = world.state.expected_nonce(&world.founder_address);
    let key = world.founder.clone();
    let cheap = Transaction::sign(
        MAINNET,
        next,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("1").unwrap(),
        },
        &key,
    );
    let rich = Transaction::sign(
        MAINNET,
        next,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("1000").unwrap(),
        },
        &key,
    );
    tiny.insert(&world.state, cheap.clone(), world.time).unwrap();
    // The better-paying transaction for the same nonce replaces the cheap one.
    tiny.insert(&world.state, rich.clone(), world.time).unwrap();
    assert_eq!(tiny.len(), 1);
    assert!(tiny.contains(&rich.id()));
    assert!(!tiny.contains(&cheap.id()));

    // A queued transaction that pays less than what the pool already holds is
    // refused outright, rather than evicting the transaction it depends on.
    let cheap_again = Transaction::sign(
        MAINNET,
        next + 1,
        TxKind::Transfer {
            to: bob_address,
            amount: Amount::parse("2").unwrap(),
        },
        &key,
    );
    match tiny.insert(&world.state, cheap_again, world.time) {
        Err(MempoolError::PoolFull { limit }) => assert_eq!(limit, 1),
        other => panic!("expected the pool limit, got {:?}", other.is_ok()),
    }
    assert!(tiny.contains(&rich.id()), "the depended-on transaction survives");
}

#[test]
fn transactions_expire_on_protocol_time() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = Mempool::new(MempoolConfig {
        expiry_secs: 600,
        ..MempoolConfig::default()
    });

    let tx = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    mempool.insert(&world.state, tx, world.time).unwrap();
    assert_eq!(mempool.expire(world.time + 600), 0, "still inside the window");
    assert_eq!(mempool.expire(world.time + 601), 1, "now stale");
    assert!(mempool.is_empty());
}

#[test]
fn a_reorganisation_returns_its_transactions_to_the_pool() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);

    let mut mempool = pool();
    let tx = world.transfer(&world.founder.clone(), bob_address, Amount::parse("1").unwrap());
    mempool.insert(&world.state, tx.clone(), world.time).unwrap();

    let founder = world.founder.clone();
    let block = world
        .state
        .build_block(&founder, world.time, vec![tx.clone()], Vec::new())
        .unwrap();
    let before = world.state.clone();
    let applied = world.state.apply_block(&block).unwrap();
    world.state = applied.state;
    assert_eq!(mempool.on_block_applied(&world.state, &block), 1);
    assert!(mempool.is_empty());

    // The block is orphaned by a reorganisation: the state reverts to before it
    // and its transactions come back to the pool.
    world.state = before;
    let restored = mempool.on_reorg(&world.state, [&block], world.time + 1);
    assert_eq!(restored, 1);
    assert!(mempool.contains(&tx.id()));
    assert_eq!(
        mempool.select_for_block(&world.state, world.time + 1, 10).len(),
        1,
        "the restored transaction is immediately usable"
    );
}

#[test]
fn a_queued_sequence_that_overdraws_the_account_is_refused() {
    let mut world = World::new();
    let bob = Keypair::from_seed(&[41u8; 32]);
    let bob_address = world.register(&bob, 1);
    let mut mempool = pool();

    let balance = world.balance(&world.founder_address);
    assert!(balance > GENESIS_ALLOCATION);

    // Two transfers that are each valid on their own, but together spend more
    // than the account holds: the second is refused because the pool validates
    // the queued sequence, not the single transaction.
    let half = balance.div_floor(2).unwrap();
    let first = world.transfer(&world.founder.clone(), bob_address, half);
    mempool.insert(&world.state, first.clone(), world.time).unwrap();
    let second = world.transfer(&world.founder.clone(), bob_address, balance);
    match mempool.insert(&world.state, second.clone(), world.time) {
        Err(MempoolError::Invalid(error)) => assert_eq!(error.rule, "tx_insufficient_funds"),
        other => panic!("expected an overdraw refusal, got {:?}", other.is_ok()),
    }
    assert_eq!(mempool.len(), 1);
    assert_eq!(mempool.stats().total_fees, obs_chain::params::gas_fee_for(half));
    assert_eq!(BASE_CLAIM_GRAINS > 0, true);
}

#[test]
fn a_pool_of_many_accounts_produces_a_template_that_always_applies() {
    let mut world = World::new();
    let mut mempool = pool();
    let mut recipients = Vec::new();
    for index in 0..5u8 {
        let key = Keypair::from_seed(&[60 + index; 32]);
        recipients.push(world.register(&key, index + 1));
    }
    // The founder queues five consecutive transfers, one per recipient.
    let founder = world.founder.clone();
    for (index, recipient) in recipients.iter().enumerate() {
        let amount = Amount::from_grains(1_000_000 + index as u128);
        let tx = world.transfer(&founder, *recipient, amount);
        mempool.insert(&world.state, tx, world.time).unwrap();
    }
    assert_eq!(mempool.len(), 5);
    assert_eq!(mempool.next_nonce(&world.state, &world.founder_address), 8);

    let template = mempool.select_for_block(&world.state, world.time, 3);
    assert_eq!(template.len(), 3, "the caller's limit is respected");
    let block = world
        .state
        .build_block(&founder, world.time, template, Vec::new())
        .unwrap();
    world.state.apply_block(&block).expect("the template applies");
}
