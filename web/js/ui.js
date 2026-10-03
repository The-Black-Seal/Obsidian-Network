// Small rendering helpers shared by the four views.
//
// Everything here builds DOM nodes rather than parsing HTML strings.  Chain data
// is attacker-influenced — an address, an endpoint, a label someone chose — and a
// UI that assembles HTML from it is a UI that runs whatever those strings
// contain.  `element()` and `textContent` make that class of bug impossible
// rather than unlikely.

import { element } from './format.js';

/** A card with a title, an optional subtitle and content. */
export function card({ title, subtitle, body, className = '', actions = [] }) {
  const header = element('div', { className: 'spread' });
  const heading = element('div');
  if (title) heading.append(element('h3', { text: title }));
  if (subtitle) heading.append(element('p', { className: 'faint', text: subtitle }));
  header.append(heading);
  if (actions.length) header.append(element('div', { className: 'row', children: actions }));
  const node = element('div', { className: `card ${className}`.trim() });
  node.append(header);
  if (body) {
    const content = element('div', { className: 'card-body' });
    content.append(body);
    node.append(content);
  }
  return node;
}

/** A labelled figure. */
export function metric(label, value, { unit, small = false, title } = {}) {
  const node = element('div', { className: 'metric', attributes: { title } });
  node.append(element('span', { className: 'label', text: label }));
  node.append(element('span', { className: `value${small ? ' small' : ''}`, text: value }));
  if (unit) node.append(element('span', { className: 'unit', text: unit }));
  return node;
}

/** A grid of cards or metrics. */
export function grid(children, columns = 3) {
  return element('div', { className: `grid cols-${columns}`, children });
}

/** A notice block. */
export function notice(text, kind = '') {
  return element('div', { className: `notice ${kind}`.trim(), text });
}

/** A notice with a bold lead-in and detailed text. */
export function noticeRich(title, detail, kind = '') {
  const node = element('div', { className: `notice ${kind}`.trim() });
  node.append(element('strong', { text: title }));
  if (detail) node.append(element('span', { text: ` ${detail}` }));
  return node;
}

/** A pill. */
export function pill(text, kind = '') {
  return element('span', { className: `pill ${kind}`.trim(), text });
}

/** A table from a header list and row arrays of nodes or strings. */
export function table(headers, rows, { empty = 'Nothing to show yet.' } = {}) {
  if (!rows.length) {
    return element('p', { className: 'faint', text: empty });
  }
  const head = element('tr');
  for (const header of headers) head.append(element('th', { text: header }));
  const body = element('tbody');
  for (const row of rows) {
    const tr = element('tr');
    for (const cell of row) {
      tr.append(cell instanceof HTMLElement ? cell : element('td', { text: String(cell) }));
    }
    body.append(tr);
  }
  const wrapper = element('div', { className: 'table-wrap' });
  wrapper.append(element('table', { children: [element('thead', { children: [head] }), body] }));
  return wrapper;
}

/** A cell that copies its value when clicked. */
export function copyable(text, label = text) {
  const button = element('button', {
    className: 'small ghost mono',
    text: label,
    attributes: { type: 'button', title: 'Copy' },
  });
  button.addEventListener('click', async () => {
    const { copy } = await import('./format.js');
    const ok = await copy(text);
    button.textContent = ok ? 'copied' : 'select and copy';
    setTimeout(() => { button.textContent = label; }, 1400);
  });
  return element('td', { children: [button] });
}

/** A labelled field row. */
export function field(label, input, hint) {
  const wrapper = element('label');
  wrapper.append(element('span', { text: label }));
  wrapper.append(input);
  if (hint) wrapper.append(element('span', { className: 'faint', text: hint }));
  return wrapper;
}

/** A text input. */
export function input({ value = '', placeholder = '', type = 'text', name, readonly = false, min, max, step }) {
  return element('input', {
    attributes: { value, placeholder, type, name, readonly, min, max, step, autocomplete: 'off', spellcheck: 'false' },
  });
}

/** A disabled-until-loaded button. */
export function button(text, { kind = '', onClick, type = 'button' } = {}) {
  const node = element('button', { className: kind, text, attributes: { type } });
  if (onClick) node.addEventListener('click', onClick);
  return node;
}

/** A definition list from pairs. */
export function pairs(items) {
  const body = element('tbody');
  for (const [key, value] of items) {
    const tr = element('tr');
    tr.append(element('td', { className: 'dim', text: key }));
    tr.append(value instanceof HTMLElement ? value : element('td', { text: String(value) }));
    body.append(tr);
  }
  const wrapper = element('div', { className: 'table-wrap' });
  wrapper.append(element('table', { children: [body] }));
  return wrapper;
}

/** The raw JSON of a response, folded away. */
export function raw(label, value) {
  const details = element('details', { className: 'raw' });
  details.append(element('summary', { text: label }));
  details.append(element('pre', { text: JSON.stringify(value, null, 2) }));
  return details;
}

/** Replaces a container's children.
 *
 * Named `replace` rather than `render` because every view exports its own
 * `render`, and a module cannot import a name it also declares.
 */
export function replace(container, ...children) {
  container.replaceChildren();
  for (const child of children) {
    if (child !== null && child !== undefined) container.append(child);
  }
  return container;
}
