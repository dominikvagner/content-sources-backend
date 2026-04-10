import { test as base } from '@playwright/test';
import {
    ensureValidToken,
    handleTokenEndpointResponse,
    usesIdentityHeaderAuth,
} from '../helpers/tokenHelpers';
import { isString } from './client';

/**
 * Autofixture that automatically refreshes JWT tokens before each test
 * based on the storageState configured for that test.
 *
 * Also installs a passive response listener that captures any token refresh
 * the app wrapper (insights-chrome) triggers during the test, keeping
 * process.env, the .auth/*.json file, and the live browser context in sync.
 */
export const tokenRefreshTest = base.extend<{ tokenRefresh: void }>({
  tokenRefresh: [async ({ page, storageState }, use, r) => {
    if (usesIdentityHeaderAuth()) {
      await use();
      return;
    }

    const storagePath = storageState ?? r.project.use.storageState;
    const storage = isString(storagePath) ? storagePath : undefined;

    // --- Pre-test proactive refresh ---
    try {
      await ensureValidToken(page, storage);
    } catch (error) {
      console.error('[Token Refresh] Failed to refresh token:', error);
    }

    // --- Passive response listener for app-initiated token refreshes ---
    page.on('response', async (response) => {
      try {
        if (
          response.url().includes('/protocol/openid-connect/token') &&
          response.status() === 200
        ) {
          const data = await response.json();
          if (data?.access_token && data?.id_token && data?.refresh_token && data?.expires_in) {
            await handleTokenEndpointResponse(data, storage ?? 'ADMIN_TOKEN.json', page);
            console.log('[Token Intercept] Captured app-initiated token refresh');
          }
        }
      } catch {}
    });

    await use();
  }, { auto: true }]
});
