import { test as oldTest } from '@playwright/test';
import {
  ensureValidToken,
  usesIdentityHeaderAuth,
} from '../helpers/tokenHelpers';

type WithCleanup = {
  cleanup: Cleanup;
};

export interface Cleanup {
  add: (cleanupFn: () => Promise<unknown>) => symbol;
  runAndAdd: (cleanupFn: () => Promise<unknown>) => Promise<symbol>;
  remove: (key: symbol) => void;
}

export const cleanupTest = oldTest.extend<WithCleanup>({
  cleanup: async ({ page, storageState }, use) => {
    const cleanupFns: Map<symbol, () => Promise<unknown>> = new Map();

    await use({
      add: (cleanupFn) => {
        const key = Symbol();
        cleanupFns.set(key, cleanupFn);
        return key;
      },
      runAndAdd: async (cleanupFn) => {
        await cleanupFn();

        const key = Symbol();
        cleanupFns.set(key, cleanupFn);
        return key;
      },
      remove: (key) => {
        cleanupFns.delete(key);
      },
    });

    if (!usesIdentityHeaderAuth()) {
      const storageStatePath = typeof storageState === 'string' ? storageState : undefined;
      try {
        await ensureValidToken(page, storageStatePath);
      } catch (error) {
        console.error('[Cleanup] Failed to ensure valid token before cleanup:', error);
      }
    }

    await cleanupTest.step(
      'Post-test cleanup',
      async () => {
        await Promise.all(Array.from(cleanupFns).map(([, fn]) => fn()));
      },
      { box: true },
    );
  },
});
