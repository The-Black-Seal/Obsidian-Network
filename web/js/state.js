// What the interface knows about the chain, and where it learned it.
//
// One store, refreshed from the node on a timer.  Every view reads from here, so
// no view can quietly fetch its own version of the truth, and nothing is
// invented: when the node is unreachable the store says so and the interface
// shows that instead of the last numbers it happened to see.  A cached chain is
// a chain that lies about how old its head is.

import { describe, explorer, node } from './api.js';

const listeners = new Set();

export const state = {
  reachable: false,
  error: null,
  at: null,
  status: null,
  supply: null,
  mining: null,
  indexStatus: null,
  authority: null,
};

let timer = null;

export function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function publish() {
  for (const listener of listeners) {
    try { listener(state); } catch (cause) { console.error(cause); }
  }
}

/** Refreshes everything the shell displays. */
export async function refresh() {
  try {
    const [status, supply, mining] = await Promise.all([
      node.status(),
      node.supply(),
      node.mining(),
    ]);
    state.status = status;
    state.supply = supply;
    state.mining = mining;
    state.reachable = true;
    state.error = null;
    state.at = new Date();
  } catch (error) {
    state.reachable = false;
    state.error = describe(error);
  }
  // The index is a separate service and may lag the node; that is shown rather
  // than hidden, which is why it is fetched separately and failures here never
  // mark the node unreachable.
  try {
    state.indexStatus = await explorer.status();
  } catch (error) {
    state.indexStatus = null;
  }
  publish();
}

/** Starts polling.  The interval is a reading cadence, not a timer anything depends on. */
export function start(intervalMs = 5000) {
  stop();
  refresh();
  timer = setInterval(refresh, intervalMs);
}

export function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

/** The chain's protocol time, which is the only clock eligibility is judged by. */
export function protocolTime() {
  return state.status ? Number(state.status.protocol_time) : null;
}

/** The index, when it is behind the node, and by how much. */
export function indexLag() {
  if (!state.status || !state.indexStatus) return null;
  const nodeHeight = Number(state.status.height);
  const indexed = Number(state.indexStatus.indexed_height);
  if (!Number.isFinite(nodeHeight) || !Number.isFinite(indexed)) return null;
  return { nodeHeight, indexed, behind: Math.max(0, nodeHeight - indexed) };
}
