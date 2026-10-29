import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { HttpClient } from '../src/net/http.js';

/**
 * The semaphore is private, and this is the one invariant worth reaching in to
 * assert: the cap the README promises held for the common case and was off by
 * one in a gap of exactly one microtask, which no request-level test reaches.
 */
interface Semaphore {
  acquire(): Promise<void>;
  release(): void;
  active: number;
}

const asSemaphore = (client: HttpClient): Semaphore => client as unknown as Semaphore;

describe('the concurrency cap', () => {
  it('is not exceeded by an acquire arriving while a waiter is being resumed', async () => {
    const sem = asSemaphore(new HttpClient({ concurrency: 2, requestsPerSecond: 1000 }));
    await sem.acquire();
    await sem.acquire();
    assert.equal(sem.active, 2, 'full');

    const waiter = sem.acquire();
    sem.release();

    // This lands between release() and the waiter resuming. release() used to
    // decrement here and let the waiter increment a microtask later, so both
    // this caller and the waiter incremented and `active` reached 3.
    const latecomer = sem.acquire();
    const settled = await Promise.race([
      latecomer.then(() => 'acquired' as const),
      new Promise<'waited'>((resolve) => setTimeout(() => resolve('waited'), 25)),
    ]);

    assert.equal(settled, 'waited', 'the slot went to the waiter, so the latecomer waits');
    await waiter;
    assert.equal(sem.active, 2, 'never above the cap');

    // Draining lets the latecomer through, so nothing is deadlocked.
    sem.release();
    await latecomer;
    assert.equal(sem.active, 2);
  });

  it('hands every queued slot on in order, and settles back to zero', async () => {
    const sem = asSemaphore(new HttpClient({ concurrency: 1, requestsPerSecond: 1000 }));
    const order: number[] = [];
    await sem.acquire();
    const queued = [0, 1, 2].map((n) =>
      sem.acquire().then(() => {
        order.push(n);
      }),
    );
    for (let i = 0; i < 4; i += 1) {
      sem.release();
      await Promise.resolve();
    }
    await Promise.all(queued);
    assert.deepEqual(order, [0, 1, 2]);
    assert.equal(sem.active, 0);
  });
});
