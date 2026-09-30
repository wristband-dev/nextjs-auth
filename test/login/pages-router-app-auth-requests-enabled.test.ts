/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, LOGIN_STATE_COOKIE_SECRET, parseSetCookies } from '../test-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { LoginState } from '../../src/types';
import { decryptLoginState, encryptLoginState } from '../../src/utils/crypto';
import { mockWristbandFetch } from '../helpers/mock-fetch';

function validateAppLevelAuthorizeRedirect(authorizeUrl: string, expectedOrigin: string, expectedRedirectUri: string) {
  const url: URL = new URL(authorizeUrl);
  const { pathname, origin, searchParams } = url;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/oauth2/authorize');

  expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
  expect(searchParams.get('redirect_uri')).toEqual(expectedRedirectUri);
  expect(searchParams.get('response_type')).toEqual('code');
  expect(searchParams.get('state')).toBeTruthy();
  expect(searchParams.get('scope')).toEqual('openid offline_access email');
  expect(searchParams.get('code_challenge')).toBeTruthy();
  expect(searchParams.get('code_challenge_method')).toEqual('S256');
  expect(searchParams.get('nonce')).toBeTruthy();
}

describe('pagesRouter.login() - Application-Level Authorization Requests', () => {
  let wristbandAuth: WristbandAuth;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    mockWristbandFetch();
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Fixed host configuration (no tenant subdomains)', () => {
    const loginUrl = 'https://localhost:6001/api/auth/login';
    const redirectUri = 'https://localhost:6001/api/auth/callback';

    test('Redirects to app-level Authorize Endpoint when tenant cannot be resolved', async () => {
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

      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        headers: { host: 'localhost:6001' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
      expect(mockRes.getHeader('Pragma')).toBe('no-cache');
      validateAppLevelAuthorizeRedirect(authorizeUrl, `https://${wristbandApplicationVanityDomain}`, redirectUri);

      // A login state cookie SHOULD be set here (unlike the applicationAuthorizationRequestsEnabled: false case)
      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(setCookieHeaders).toBeTruthy();
      expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      const loginStateCookie = parsedCookies[0];
      const keyParts: string[] = loginStateCookie.name.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts[0]).toEqual('login');

      // No parseTenantFromRootDomain configured, so no Domain attribute should be set
      expect(loginStateCookie.domain).toBeUndefined();
      expect(loginStateCookie.httponly).toBe(true);
      expect(loginStateCookie['max-age']).toBe('3600');
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBe(true);

      const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(new URL(authorizeUrl).searchParams.get('state')).toEqual(keyParts[1]);
    });

    test('Ignores customApplicationLoginPageUrl when applicationAuthorizationRequestsEnabled is true', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        customApplicationLoginPageUrl: 'https://custom-login.example.com',
        autoConfigureEnabled: false,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        headers: { host: 'localhost:6001' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Should go to the app-level Authorize Endpoint, NOT the custom login page
      expect(new URL(authorizeUrl).origin).toEqual(`https://${wristbandApplicationVanityDomain}`);
      expect(new URL(authorizeUrl).pathname).toEqual('/api/v1/oauth2/authorize');
    });

    test('Uses dangerouslyDisableSecureCookies flag on the app-level login state cookie', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        dangerouslyDisableSecureCookies: true,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        applicationAuthorizationRequestsEnabled: true,
        autoConfigureEnabled: false,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        headers: { host: 'localhost:6001' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      expect(parsedCookies[0].secure).toBeUndefined();
    });

    test('Includes idp_hint and login_hint query params on the app-level Authorize URL', async () => {
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

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?idp_hint=google&login_hint=user@example.com`,
        headers: { host: 'localhost:6001' },
        query: { idp_hint: 'google', login_hint: 'user@example.com' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      const { searchParams } = new URL(authorizeUrl);

      expect(searchParams.get('idp_hint')).toBe('google');
      expect(searchParams.get('login_hint')).toBe('user@example.com');
    });

    test('Clears stale login state cookies before setting the new one', async () => {
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

      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01 = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02 = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03 = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        cookies: {
          'login#++state01#1111111111': encryptedLoginState01,
          'login#state02#2222222222': encryptedLoginState02,
          'login#state03#3333333333': encryptedLoginState03,
        },
        headers: { host: 'localhost:6001' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect((setCookieHeaders as string[]).length).toBe(2);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      const oldCookie = parsedCookies.find((c) => {
        return c.name === 'login#++state01#1111111111';
      });
      expect(oldCookie).toBeTruthy();
      expect(oldCookie!.value).toBeFalsy();
      expect(oldCookie!['max-age']).toBe('0');
    });
  });

  describe('Tenant subdomain configuration (parseTenantFromRootDomain set)', () => {
    const parseTenantFromRootDomain = 'business.invotastic.com';
    const loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
    const redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

    test('Sets the login state cookie with a Domain attribute scoped to parseTenantFromRootDomain', async () => {
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

      // No subdomain present on the host, so tenant cannot be resolved
      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expect(new URL(authorizeUrl).origin).toEqual(`https://${wristbandApplicationVanityDomain}`);
      expect(new URL(authorizeUrl).pathname).toEqual('/api/v1/oauth2/authorize');

      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].domain).toBe(`.${parseTenantFromRootDomain}`);
    });

    test('Clears stale login state cookies with the matching Domain attribute', async () => {
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

      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01 = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02 = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03 = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      // No subdomain present, so tenant cannot be resolved and this hits the app-level branch
      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
        cookies: {
          'login#++state01#1111111111': encryptedLoginState01,
          'login#state02#2222222222': encryptedLoginState02,
          'login#state03#3333333333': encryptedLoginState03,
        },
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(Array.isArray(setCookieHeaders)).toBe(true);
      expect((setCookieHeaders as string[]).length).toBe(2);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      const oldCookie = parsedCookies.find((c) => {
        return c.name === 'login#++state01#1111111111';
      });
      expect(oldCookie).toBeTruthy();
      expect(oldCookie!['max-age']).toBe('0');
      expect(oldCookie!.domain).toBe(`.${parseTenantFromRootDomain}`);

      const newCookie = parsedCookies.find((c) => {
        return c.name !== 'login#++state01#1111111111';
      });
      expect(newCookie!.domain).toBe(`.${parseTenantFromRootDomain}`);
    });
  });

  describe('Tenant resolvable - applicationAuthorizationRequestsEnabled has no effect', () => {
    test('Uses the normal tenant-level flow when a tenant_name is resolvable, even with the flag enabled', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

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

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
        headers: { host: parseTenantFromRootDomain },
        query: { tenant_name: 'devs4you' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Should hit the tenant-level Authorize Endpoint (hyphen-separated), not the app-level one
      expect(new URL(authorizeUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
