// Tests for the interface's own arithmetic and masking.
//
// Run with:  node --test web/tests/
//
// The important one is the amount formatting.  OBS has twelve decimal places and
// a claim is worth 0.000166666666 — a value a JavaScript number cannot hold
// exactly.  If the interface parsed amounts as numbers it would disagree with the
// chain about how much money somebody has, which is the one thing a wallet's
// front end must never do.  These tests pin the string arithmetic.

import test from 'node:test';
import assert from 'node:assert/strict';

import { installDom } from './dom.mjs';
import {
  amount, amountWhole, basisPoints, duration, element, grains, partialAddress, shortHash,
  splitAmount, until,
} from '../js/format.js';

// `element` builds DOM nodes, so these tests need the small DOM the other
// interface tests use.  Installing it is enough; no page is loaded.
installDom();

test('an amount keeps every digit and is never a float', () => {
  // The value a claim is worth.  As a JavaScript number this is 0.000166666666
  // and, in binary, something slightly different; as a string it is exact.
  assert.equal(amount('0.000166666666', { unit: false }), '0.000166666666');
  assert.equal(amount('100000.000166666666', { unit: false }), '100,000.000166666666');
  assert.equal(amount('21000000', { unit: false }), '21,000,000');
  assert.equal(amount('21000000'), '21,000,000 OBS');

  // Precision is never dropped silently.
  assert.equal(amount('1.000000000001', { unit: false }), '1.000000000001');
  assert.equal(amount('0.100000000000', { unit: false }), '0.100000000000');

  // Trimming is opt-in, and only then.
  assert.equal(amount('1.230000000000', { unit: false, trim: true }), '1.23');
});

test('a whole-coin headline does not round the fraction away', () => {
  assert.equal(amountWhole('100000.000166666666'), '100,000');
  assert.equal(amountWhole('21000000'), '21,000,000');
});

test('grams of the smallest unit are exact', () => {
  // 1 OBS = 1,000,000,000,000 grains.
  assert.equal(grains('1'), '1000000000000');
  assert.equal(grains('0.000166666666'), '166666666');
  assert.equal(grains('100000.000166666666'), '100000000166666666');
});

test('splitting an amount does no arithmetic at all', () => {
  assert.deepEqual(splitAmount('123.456'), { negative: false, whole: '123', fraction: '456' });
  assert.deepEqual(splitAmount('-0.5'), { negative: true, whole: '0', fraction: '5' });
  assert.deepEqual(splitAmount('7'), { negative: false, whole: '7', fraction: '' });
});

test('an address is shown partially, the way the explorer publishes one', () => {
  const address = 'dobs1aelkaycnsdhgpkozz32wa7pd3si6qw5hp6ot7bto';
  const shown = partialAddress(address);
  assert.equal(shown, 'dobs1aelka…ot7bto');
  assert.ok(shown.includes('…'));
  // A short value is not mangled into something unreadable.
  assert.equal(partialAddress('dobs1abc'), 'dobs1abc');
});

test('a hash is shortened without losing its ends', () => {
  const hash = 'd80927e93c75ae02507ee2e44f604d643a9e49d953b2440a7ec1b37263326874';
  assert.equal(shortHash(hash), 'd80927e93c75…63326874');
  assert.equal(shortHash('abcd'), 'abcd');
});

test('basis points read as percentages', () => {
  assert.equal(basisPoints(10_000), '100%');
  assert.equal(basisPoints(9_950), '99.50%');
  assert.equal(basisPoints(50), '0.50%');
  assert.equal(basisPoints(0), '0%');
});

test('durations and countdowns are expressed in units a person can act on', () => {
  assert.equal(duration(0), 'now');
  assert.equal(duration(45), '45 seconds');
  assert.equal(duration(600), '10 minutes');
  assert.equal(duration(14_400), '4.0 hours');
  assert.equal(duration(172_800), '2.0 days');

  // Eligibility is judged against the chain's clock, so the countdown is too.
  assert.equal(until(1_000, 1_000), 'now');
  assert.equal(until(1_000, 400), 'in 10 minutes');
  // A missing chain time yields no countdown at all, rather than a wrong one.
  assert.equal(until(undefined, 10), '');
  assert.equal(until(1_000, undefined), '');
});

test('element() keeps the children it is given, however they are passed', () => {
  // Positional children — the form every view uses.
  const hero = element('div', { className: 'hero' },
    element('h1', { text: 'Mining' }),
    element('p', { text: 'Proof of time.' }));
  assert.equal(hero.querySelector('h1').textContent, 'Mining');
  assert.equal(hero.querySelector('p').textContent, 'Proof of time.');

  // An array in the third position — also used.
  const row = element('div', { className: 'row' }, [
    element('span', { text: 'one' }),
    element('span', { text: 'two' }),
  ]);
  assert.equal(row.querySelectorAll('span').length, 2);

  // The options form.
  const list = element('ul', { children: [element('li', { text: 'first' })] });
  assert.equal(list.querySelector('li').textContent, 'first');

  // A null child is skipped rather than rendered as "null".
  const mixed = element('div', {}, null, undefined, false, element('b', { text: 'kept' }));
  assert.equal(mixed.textContent, 'kept');
});
