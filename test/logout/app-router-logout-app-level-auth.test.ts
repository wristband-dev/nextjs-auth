import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, createMockNextRequest, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { mockWristbandFetch } from '../helpers/mock-fetch';

describe('appRouter.logout() - Application-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    mockWristbandFetch();
  });

  describe('Tenant subdomain configuration (loginUrl contains a placeholder)', () => {
    describe.each([['{tenant_domain}'], ['{tenant_name}']])('with %s placeholder', (placeholder) => {
      test('Falls back to fallbackLoginUrl when tenant cannot be resolved', async () => {
        const parseTenantFromRootDomain = 'business.invotastic.com';
        const wristbandApplicationVanityDomain = 'auth.invotastic.com';
        const loginUrl = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/login`;
        const redirectUri = `https://${placeholder}.${parseTenantFromRootDomain}/api/auth/callback`;
        const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

        wristbandAuth = createWristbandAuth({
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl,
          redirectUri,
          parseTenantFromRootDomain,
          wristbandApplicationVanityDomain,
          applicationAuthorizationRequestsEnabled: true,
          fallbackLoginUrl,
          autoConfigureEnabled: false,
        });

        // No subdomain present on the host, so tenant cannot be resolved
        const { req } = createMocks({
          method: 'GET',
          url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
          headers: { host: parseTenantFromRootDomain },
        });
        const mockNextRequest = createMockNextRequest(req);

        const response = await wristbandAuth.appRouter.logout(mockNextRequest);

        expect(response.status).toBe(302);
        expect(response.headers.get('location')).toBe(fallbackLoginUrl);
      });
    });
  });

  describe('Fixed host configuration (loginUrl has no placeholder)', () => {
    test('Falls back directly to loginUrl when tenant cannot be resolved', async () => {
      const wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';
      const loginUrl = 'https://localhost:6001/api/auth/login';
      const redirectUri = 'https://localhost:6001/api/auth/callback';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://localhost:6001/api/auth/logout`,
        headers: { host: 'localhost:6001' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest);

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(loginUrl);
    });
  });

  describe('Priority ordering', () => {
    test('config.redirectUrl still takes precedence over the app-level fallback', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const wristbandApplicationVanityDomain = 'auth.invotastic.com';
      const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
      const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest, {
        redirectUrl: 'https://redirect.example.com',
      });

      // NextResponse.redirect() re-serializes a bare-origin URL through the URL constructor,
      // which appends a trailing slash -- https://redirect.example.com becomes .../  here.
      expect(response.headers.get('location')).toBe('https://redirect.example.com/');
    });

    test('Resolves the normal tenant-level logout URL when a tenant is resolvable, even with the flag enabled', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const wristbandApplicationVanityDomain = 'auth.invotastic.com';
      const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
      const fallbackLoginUrl = 'https://fallback.invotastic.com/login';

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `https://devs4you.${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.logout(mockNextRequest);
      const location = response.headers.get('location') as string;

      expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
