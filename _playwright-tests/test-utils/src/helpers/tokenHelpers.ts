import { type Page } from '@playwright/test';
import path from 'path';
import { readFileSync, writeFileSync, existsSync } from 'fs';

interface StorageState {
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite: string;
  }>;
  origins: Array<{
    origin: string;
    localStorage: Array<{ name: string; value: string }>;
  }>;
}

interface TokenRefreshResult {
  accessToken: string;
  refreshToken: string;
  idToken?: string;
  expiresAt: number;
}

function resolveAuthStorageRoot(): string {
  return process.env.PLAYWRIGHT_AUTH_DIR ?? path.join(__dirname, '../../../.auth');
}

export function resolveStorageStatePath(fileNameOrPath: string): string {
  if (path.isAbsolute(fileNameOrPath)) return fileNameOrPath;
  if (existsSync(fileNameOrPath)) return path.resolve(fileNameOrPath);
  return path.join(resolveAuthStorageRoot(), path.basename(fileNameOrPath));
}

function getFileNameFromAuthPath(authPath: string): string {
  return authPath.replace('.auth/', '');
}

function fileNameToEnvVar(fileName: string): string {
  return fileName.replace('.json', '');
}

export function envVarForPath(storageStatePath?: string): string {
  const fileName = storageStatePath?.endsWith('.json')
    ? getFileNameFromAuthPath(storageStatePath)
    : 'ADMIN_TOKEN.json';
  return fileNameToEnvVar(fileName);
}

export function usesIdentityHeaderAuth(): boolean {
  return Boolean(process.env.IDENTITY_HEADER?.trim());
}

function decodeJWT(token: string): { exp: number } | null {
  try {
    const payload = token.replace(/^Bearer\s+/i, '').split('.')[1];
    const buffer = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    return JSON.parse(buffer.toString());
  } catch {
    return null;
  }
}

function isTokenExpiring(token: string, bufferMinutes: number): boolean {
  const payload = decodeJWT(token);
  if (!payload?.exp) return true;
  return payload.exp * 1000 - Date.now() <= bufferMinutes * 60_000;
}

function readStorageState(filePath: string): StorageState {
  return JSON.parse(readFileSync(filePath, 'utf-8'));
}

function getTokenFromStorageState(filePath: string): string | null {
  try {
    const storage = readStorageState(filePath);

    const localStorageToken = storage.origins?.[0]?.localStorage?.find(
      (i) => i.name === 'cs_jwt',
    );
    if (localStorageToken?.value) {
      return localStorageToken.value.startsWith('Bearer ')
        ? localStorageToken.value
        : `Bearer ${localStorageToken.value}`;
    }

    const cookie = storage.cookies?.find((c) => c.name === 'cs_jwt');
    if (cookie?.value) return `Bearer ${cookie.value}`;

    return null;
  } catch {
    return null;
  }
}

function updateStorageStateFile(
  filePath: string,
  storage: StorageState,
  tokenData: { access_token: string; refresh_token?: string; id_token?: string; expires_in?: number },
  oidcEntryKey: string,
) {
  if (!tokenData.access_token || typeof tokenData.access_token !== 'string') return;

  const newExpires = Math.floor(Date.now() / 1000) + (tokenData.expires_in ?? 900);

  for (const cookie of storage.cookies ?? []) {
    if (cookie.name === 'cs_jwt') {
      cookie.value = tokenData.access_token;
      cookie.expires = newExpires;
    }
  }

  for (const origin of storage.origins ?? []) {
    for (const item of origin.localStorage ?? []) {
      if (item.name === oidcEntryKey) {
        const oidcUser = JSON.parse(item.value);
        oidcUser.access_token = tokenData.access_token;
        oidcUser.expires_at = newExpires;
        if (tokenData.refresh_token) oidcUser.refresh_token = tokenData.refresh_token;
        if (tokenData.id_token) oidcUser.id_token = tokenData.id_token;
        item.value = JSON.stringify(oidcUser);
      }
    }
  }

  writeFileSync(filePath, JSON.stringify(storage, null, 2), 'utf-8');
}

function getOidcUserEntry(storage: StorageState) {
  for (const origin of storage.origins ?? []) {
    for (const item of origin.localStorage ?? []) {
      if (item.name.startsWith('oidc.user:')) {
        return { key: item.name, value: JSON.parse(item.value) as Record<string, unknown> };
      }
    }
  }
  return null;
}

function parseOidcKey(oidcKey: string) {
  const withoutPrefix = oidcKey.replace(/^oidc\.user:/, '');
  const lastColon = withoutPrefix.lastIndexOf(':');
  const authority = (lastColon > 0 ? withoutPrefix.substring(0, lastColon) : withoutPrefix).replace(/\/+$/, '');
  const clientId = lastColon > 0 ? withoutPrefix.substring(lastColon + 1) : 'cloud-services';
  return {
    tokenEndpoint: `${authority}/realms/redhat-external/protocol/openid-connect/token`,
    clientId,
  };
}

export async function refreshTokenViaEndpoint(page: Page, storageStatePath: string): Promise<TokenRefreshResult> {
  const absolutePath = resolveStorageStatePath(storageStatePath);
  const storage = readStorageState(absolutePath);

  const oidcEntry = getOidcUserEntry(storage);
  if (!oidcEntry) throw new Error(`No oidc.user entry in ${storageStatePath}`);

  const refreshToken = oidcEntry.value.refresh_token as string | undefined;
  if (!refreshToken) throw new Error(`No refresh_token in ${storageStatePath}`);

  const { tokenEndpoint, clientId } = parseOidcKey(oidcEntry.key);

  const response = await page.request.fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    data: new URLSearchParams({
      grant_type: 'refresh_token',
      scope: "openid roles api.console web-origins api.ask_red_hat",
      client_id: clientId,
      refresh_token: refreshToken,
    }).toString(),
  });

  if (!response.ok()) {
    const body = await response.text();
    throw new Error(`Token refresh failed (${response.status}): ${body}`);
  }

  const data = await response.json();
  updateStorageStateFile(absolutePath, storage, data, oidcEntry.key);

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
    expiresAt: Math.floor(Date.now() / 1000) + data.expires_in,
  };
}

async function syncTokenToPageContext(page: Page, result: TokenRefreshResult) {
  const existingCookies = await page.context().cookies();
  const csJwtCookies = existingCookies.filter((c) => c.name === 'cs_jwt');

  if (csJwtCookies.length > 0) {
    await page.context().clearCookies({ name: 'cs_jwt' });
    await page.context().addCookies(
      csJwtCookies.map((c) => ({ ...c, value: result.accessToken, expires: result.expiresAt })),
    );
  }

  try {
    await page.evaluate(
      ({ token, refresh, idToken, expiresAt }) => {
        const key = Object.keys(localStorage).find((k) => k.startsWith('oidc.user:'));
        if (key) {
          const user = JSON.parse(localStorage.getItem(key)!);
          user.access_token = token;
          user.expires_at = expiresAt;
          if (refresh) user.refresh_token = refresh;
          if (idToken) user.id_token = idToken;
          localStorage.setItem(key, JSON.stringify(user));
        }
      },
      { token: result.accessToken, refresh: result.refreshToken, idToken: result.idToken, expiresAt: result.expiresAt },
    );
  } catch {
    // No origin loaded (API-only tests) -- localStorage is irrelevant
  }
}

export async function handleTokenEndpointResponse(
  tokenData: { access_token: string; refresh_token?: string; id_token?: string; expires_in?: number },
  storageStatePath: string,
  page?: Page,
) {
  if (!tokenData.access_token || typeof tokenData.access_token !== 'string') return;

  const result: TokenRefreshResult = {
    accessToken: tokenData.access_token,
    refreshToken: tokenData.refresh_token ?? '',
    idToken: tokenData.id_token,
    expiresAt: Math.floor(Date.now() / 1000) + (tokenData.expires_in ?? 900),
  };

  process.env[envVarForPath(storageStatePath)] = `Bearer ${result.accessToken}`;

  try {
    const absolutePath = resolveStorageStatePath(storageStatePath);
    const storage = readStorageState(absolutePath);
    const oidcEntry = getOidcUserEntry(storage);
    if (oidcEntry) {
      updateStorageStateFile(absolutePath, storage, tokenData, oidcEntry.key);
    }
  } catch {
    console.error('[Token Refresh] Failed to update storage state file on disk');
  }

  if (page) await syncTokenToPageContext(page, result);
}

const BUFFER_MINUTES = 10;

export async function ensureValidToken(
  page: Page,
  storageStatePath?: string,
  retries = 3,
) {
  const filePath = resolveStorageStatePath(
    storageStatePath ?? 'ADMIN_TOKEN.json',
  );
  const envVar = envVarForPath(storageStatePath);

  // Resolve current token: file -> env -> page cookies
  let token =
    getTokenFromStorageState(filePath) ??
    process.env[envVar] ??
    null;

  if (!token && page) {
    const cookies = await page.context().cookies();
    const jwtCookie = cookies.find((c) => c.name === 'cs_jwt');
    if (jwtCookie) token = `Bearer ${jwtCookie.value}`;
  }

  if (!token) throw new Error(`No token found for ${envVar}`);
  if (!isTokenExpiring(token, BUFFER_MINUTES)) return;

  // Refresh with retries
  let lastError: Error | null = null;
  for (let i = 0; i <= retries; i++) {
    try {
      const result = await refreshTokenViaEndpoint(page, filePath);
      process.env[envVar] = `Bearer ${result.accessToken}`;
      if (page) await syncTokenToPageContext(page, result);
      console.log(`[Token Refresh] Refreshed ${envVar}`);
      return;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError!;
}
