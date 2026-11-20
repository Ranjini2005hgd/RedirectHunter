'use strict';

/** Run async `worker(item)` over `items` with at most `limit` in flight. */
async function runPool(items, limit, worker) {
  let i = 0;
  const lanes = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (i < items.length) {
      const item = items[i++];
      await worker(item);
    }
  });
  await Promise.all(lanes);
}

module.exports = { runPool };
