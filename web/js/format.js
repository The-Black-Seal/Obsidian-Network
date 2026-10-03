// Formatting, without floating point.
//
// OBS is a 12-decimal coin and the smallest unit — one grain — is a whole number.
// Every amount the services send is a decimal *string*; this module never turns
// one into a JavaScript number, because a number is a binary float and
// 100,000.000166666666 is not exactly representable in one.  A UI that rounds a
// balance to a float is a UI that can disagree with the chain about how much
// money somebody has, so the conversion is done on the string, digit by digit.
//
// Addresses get the same treatment for a different reason: the explorer's
// contract is to publish participants only in partial form, so masking here is a
// second pair of eyes on a rule the API already enforces.

/** Splits "100000.000166666666" into its parts without arithmetic. */
export function splitAmount(text) {
  const value = String(text ?? '0').trim();
  const negative = value.startsWith('-');
  const body = negative ? value.slice(1) : value;
  const [whole = '0', fraction = ''] = body.split('.');
  return { negative, whole, fraction };
}

/** Groups the integer part: 21000000 -> "21,000,000". */
function group(digits) {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * An amount as it should be read: full precision, grouped, with its unit.
 *
 * Precision is never reduced silently.  A UI that shows "100,000" for a balance
 * of 100,000.000166666666 is lying by omission, and on a chain where a claim is
 * worth 0.000166666666 OBS every digit matters.
 */
export function amount(text, { unit = true, trim = false } = {}) {
  const { negative, whole, fraction } = splitAmount(text);
  let digits = fraction;
  if (trim) {
    digits = digits.replace(/0+$/, '');
  }
  const rendered = digits ? `${group(whole)}.${digits}` : group(whole);
  return `${negative ? '-' : ''}${rendered}${unit ? ' OBS' : ''}`;
}

/** The integer part only, for a headline figure. */
export function amountWhole(text) {
  const { negative, whole } = splitAmount(text);
  return `${negative ? '-' : ''}${group(whole)}`;
}

/** An amount in grains, as an integer string. */
export function grains(text) {
  const { negative, whole, fraction } = splitAmount(text);
  const padded = (fraction + '000000000000').slice(0, 12);
  return `${negative ? '-' : ''}${whole}${padded}`.replace(/^0+(?=\d)/, '');
}

/** A duration in seconds, in words a person can act on. */
export function duration(seconds) {
  const total = Number(seconds);
  if (!Number.isFinite(total) || total <= 0) return 'now';
  if (total < 90) return `${Math.round(total)} seconds`;
  const minutes = total / 60;
  if (minutes < 90) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)} hours`;
  const days = hours / 24;
  return `${days.toFixed(1)} days`;
}

/** A protocol timestamp, both exactly and as the time remaining. */
export function moment(unixSeconds) {
  const value = Number(unixSeconds);
  if (!Number.isFinite(value) || value <= 0) return '—';
  const date = new Date(value * 1000);
  return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

/** How long until a protocol time, from the chain's own clock. */
export function until(unixSeconds, chainNow) {
  const target = Number(unixSeconds);
  const now = Number(chainNow);
  if (!Number.isFinite(target) || !Number.isFinite(now)) return '';
  return target <= now ? 'now' : `in ${duration(target - now)}`;
}

/**
 * A partial address, the way the explorer publishes one.
 *
 * `obs1q9x7…4k8m` for a long address; short values are left alone.  The API
 * already masks what it returns, so this is belt and braces on a contract that
 * matters: an explorer that publishes whole addresses is publishing a list of
 * who holds what.
 */
export function partialAddress(text, { head = 10, tail = 6 } = {}) {
  const value = String(text ?? '');
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** Shortens a hash for a table cell, keeping both ends. */
export function shortHash(text, { head = 12, tail = 8 } = {}) {
  const value = String(text ?? '');
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/** A basis-point figure as a percentage, without floating point rounding. */
export function basisPoints(value) {
  const points = Number(value);
  if (!Number.isFinite(points)) return '—';
  const whole = Math.trunc(points / 100);
  const remainder = Math.abs(points % 100);
  return remainder === 0 ? `${whole}%` : `${whole}.${String(remainder).padStart(2, '0')}%`;
}

/** Escapes text for insertion into HTML. */
export function escapeHtml(text) {
  return String(text ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[character]));
}

/** Builds a DOM element from a small description. Never parses HTML strings. */
export function element(tag, { className, text, attributes = {}, children = [] } = {}, ...content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const [name, value] of Object.entries(attributes)) {
    if (value === null || value === undefined || value === false) continue;
    node.setAttribute(name, String(value));
  }
  // Children may be passed either in the options (`{children: [...]}`) or as
  // further arguments, one node or an array each.  Both are accepted because
  // both read well and a single call style that silently ignores one of them is
  // how a view ends up missing half its content.
  const flat = [];
  const push = (item) => {
    if (item === null || item === undefined || item === false) return;
    if (Array.isArray(item)) {
      for (const nested of item) push(nested);
      return;
    }
    flat.push(item);
  };
  push(children);
  for (const item of content) push(item);
  for (const child of flat) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

/** Copies text to the clipboard, reporting whether it worked. */
export async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (cause) {
    return false;
  }
}
