import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import {
  CLIENT_ID,
  CLIENT_SECRET,
  createMockNextRequest,
  LOGIN_STATE_COOKIE_SECRET,
  parseSetCookies,
} from '../test-utils';
import { mockWristbandFetch } from '../helpers/mock-fetch';

const APP_HOME_URL = 'https://myapp.com/home';

describe('appRouter.createCallbackResponse() - Application-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    mockWristbandFetch();
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Tenant subdomain configuration (parseTenantFromRootDomain set)', () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    test('Clears the cookie with a Domain attribute when the flag is enabled', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        fallbackLoginUrl: `https://${wristbandApplicationVanityDomain}/login`,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state`,
        headers: { host: parseTenantFromRootDomain, cookie: 'login#state#1234567890=encrypted-login-state' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, APP_HOME_URL);

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(APP_HOME_URL);

      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders);
      const clearedCookie = parsedCookies[0];
      expect(clearedCookie.name).toBe('login#state#1234567890');
      expect(clearedCookie.value).toBeFalsy();
      expect(clearedCookie['max-age']).toBe('0');
      expect(clearedCookie.domain).toBe(`.${parseTenantFromRootDomain}`);
    });

    test('Clears the cookie without a Domain attribute when the flag is disabled', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: false,
        autoConfigureEnabled: false,
      });

      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state`,
        headers: { host: parseTenantFromRootDomain, cookie: 'login#state#1234567890=encrypted-login-state' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, APP_HOME_URL);

      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders);
      // Even though parseTenantFromRootDomain is set, the Domain attribute is only added when
      // applicationAuthorizationRequestsEnabled is also true -- the cookie in login() would never
      // have been scoped to the root domain in the first place for this configuration.
      expect(parsedCookies[0].domain).toBeUndefined();
    });
  });

  describe('Fixed host configuration (no parseTenantFromRootDomain)', () => {
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    test('Clears the cookie without a Domain attribute when parseTenantFromRootDomain is unset', async () => {
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
        url: `${redirectUri}?state=state`,
        headers: { host: 'localhost:6001', cookie: 'login#state#1234567890=encrypted-login-state' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, APP_HOME_URL);

      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders);
      expect(parsedCookies[0].domain).toBeUndefined();
    });

    test('Does not set any Set-Cookie header when no login state cookie is present', async () => {
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
        url: `${redirectUri}?state=state`,
        headers: { host: 'localhost:6001' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const response = await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, APP_HOME_URL);

      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(APP_HOME_URL);

      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toHaveLength(0);
    });
  });
});
