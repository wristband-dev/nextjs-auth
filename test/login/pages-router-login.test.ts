/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, LOGIN_STATE_COOKIE_SECRET, parseSetCookies } from '../test-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR, STATE_PARAM_MAX_CHAR_LENGTH } from '../../src/utils/constants';
import { LoginState } from '../../src/types';
import { decryptLoginState, encryptLoginState } from '../../src/utils/auth/common-utils';
import { mockWristbandFetch } from '../helpers/mock-fetch';

function validateRedirectResponse(
  mockRes: MockResponse<NextApiResponse>,
  authorizeUrl: string,
  expectedOrigin: string,
  expectedRedirectUri: string
) {
  expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
  expect(mockRes.getHeader('Pragma')).toBe('no-cache');

  const url: URL = new URL(authorizeUrl);
  const { pathname, origin, searchParams } = url;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/oauth2/authorize');

  // Validate query parameters of the Authorize URL
  expect(searchParams.get('client_id')).toEqual(CLIENT_ID);
  expect(searchParams.get('redirect_uri')).toEqual(expectedRedirectUri);
  expect(searchParams.get('response_type')).toEqual('code');
  expect(searchParams.get('state')).toBeTruthy();
  expect(searchParams.get('scope')).toEqual('openid offline_access email');
  expect(searchParams.get('code_challenge')).toBeTruthy();
  expect(searchParams.get('code_challenge_method')).toEqual('S256');
  expect(searchParams.get('nonce')).toBeTruthy();
  expect(searchParams.get('login_hint')).toBeFalsy();
  expect(searchParams.get('idp_hint')).toBeFalsy();
}

async function validateLoginStateCookie(
  mockRes: MockResponse<NextApiResponse>,
  authorizeUrl: string,
  expectedRedirectUri: string
) {
  const locationUrl: URL = new URL(authorizeUrl);
  const { searchParams } = locationUrl;
  const setCookieHeaders = mockRes.getHeader('Set-Cookie');
  expect(setCookieHeaders).toBeTruthy();
  expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

  const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
  const loginStateCookie = parsedCookies[0];
  const cookieKey: string = loginStateCookie.name;
  expect(cookieKey).toBeTruthy();
  const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
  expect(keyParts).toHaveLength(3);
  expect(keyParts[0]).toEqual('login');
  expect(keyParts[1]).toBeTruthy();
  expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

  expect(loginStateCookie.httponly).toBe(true);
  expect(loginStateCookie['max-age']).toBe('3600');
  expect(loginStateCookie.path).toBe('/');
  expect(loginStateCookie.samesite).toBe('Lax');
  expect(loginStateCookie.secure).toBe(true);

  const cookieValue: string = loginStateCookie.value;
  expect(cookieValue).toBeTruthy();
  const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
  expect(loginState.state).toEqual(keyParts[1]);
  expect(searchParams.get('state')).toEqual(keyParts[1]);
  expect(loginState.codeVerifier).toBeTruthy();
  expect(loginState.redirectUri).toBe(expectedRedirectUri);
  expect(loginState.customState).toBeUndefined();
  expect(loginState.returnUrl).toBeUndefined();
}

describe('pagesRouter.login()', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    mockWristbandFetch();
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Call login with the mock request and response
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate location header
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Dangerously Disable Secure Cookies Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        dangerouslyDisableSecureCookies: true,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Call login with the mock request and response
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );

      const locationUrl: URL = new URL(authorizeUrl);
      const { searchParams } = locationUrl;

      // Validate login state cookie
      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(setCookieHeaders).toBeTruthy();
      expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      const loginStateCookie = parsedCookies[0];
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      expect(loginStateCookie.httponly).toBe(true);
      expect(loginStateCookie['max-age']).toBe('3600');
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBeUndefined();

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);

      // App-level authorization requests are not enabled, so the cookie stays host-only
      // even though the loginUrl contains the tenant placeholder.
      const parsedCookies = parseSetCookies(mockRes.getHeader('Set-Cookie') as string | string[]);
      expect(parsedCookies[0].domain).toBeUndefined();
    });

    test('Tenant Subdomains Behind a Trusted Proxy Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
        trustProxyHeaders: true,
      });

      // The proxy forwards to an internal host, so the tenant subdomain is only in X-Forwarded-Host.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: {
          host: 'internal-app:3000',
          'x-forwarded-host': `devs4you.${parseTenantFromRootDomain}`,
        },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you.${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains with Tenant Custom Domain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: { tenant_custom_domain: 'tenant.custom.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, authorizeUrl, `https://tenant.custom.com`, redirectUri);
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains with All Domain Params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `${parseTenantFromRootDomain}` },
        query: { tenant_name: 'devs4you', tenant_custom_domain: 'tenant.custom.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, authorizeUrl, `https://tenant.custom.com`, redirectUri);
      await validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('With login_hint, idp_hint, and return_url query params', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        query: {
          idp_hint: 'google',
          login_hint: 'test@wristband.dev',
          return_url: `https://devs4you.${parseTenantFromRootDomain}/settings`,
        },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      const locationUrl: URL = new URL(authorizeUrl);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('login_hint')).toBe('test@wristband.dev');
      expect(searchParams.get('idp_hint')).toBe('google');

      // Validate login state cookie
      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(setCookieHeaders).toBeTruthy();
      expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(1);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      const loginStateCookie = parsedCookies[0];
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.returnUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/settings`);
    });

    test('Clear old login state cookie', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Mock login states
      const loginState01: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: '++state01' };
      const loginState02: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state02' };
      const loginState03: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state03' };
      const encryptedLoginState01: string = await encryptLoginState(loginState01, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState02: string = await encryptLoginState(loginState02, LOGIN_STATE_COOKIE_SECRET);
      const encryptedLoginState03: string = await encryptLoginState(loginState03, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        cookies: {
          'login#++state01#1111111111': encryptedLoginState01,
          'login#state02#2222222222': encryptedLoginState02,
          'login#state03#3333333333': encryptedLoginState03,
        },
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      // Validate Redirect response
      const locationUrl: URL = new URL(authorizeUrl);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate old login state cookie is getting cleared
      const setCookieHeaders = mockRes.getHeader('Set-Cookie');
      expect(setCookieHeaders).toBeTruthy();
      expect(Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]).toHaveLength(2);

      const parsedCookies = parseSetCookies(setCookieHeaders as string | string[]);
      expect(Object.keys(parsedCookies)).toHaveLength(2);
      const oldLoginStateCookie = parsedCookies[0];
      const oldCookieName = oldLoginStateCookie.name;
      expect(oldCookieName).toBe('login#++state01#1111111111');
      const oldCookieValue = oldLoginStateCookie.value;
      expect(oldCookieValue).toBeFalsy();

      expect(oldLoginStateCookie.httponly).toBe(true);
      expect(oldLoginStateCookie['max-age']).toBe('0');
      expect(oldLoginStateCookie.path).toBe('/');
      expect(oldLoginStateCookie.samesite).toBe('Lax');
      expect(oldLoginStateCookie.secure).toBe(true);
      expect(oldLoginStateCookie.domain).toBeUndefined();

      // Validate new login state cookie
      const loginStateCookie = parsedCookies[1];
      expect(loginStateCookie.domain).toBeUndefined();
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState = (await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET)) as LoginState;
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenant_name and tenant_custom_domain query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // tenant_name and tenant_custom_domain query param is missing, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('return_url query param is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/settings';
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
        query: { return_url: returnUrl },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
      expect(mockRes.getHeader('Set-Cookie')).toBeUndefined();
    });

    test('LoginConfig returnUrl is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/dashboard';
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
    });

    test('LoginConfig returnUrl takes precedence over return_url query param for state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
        query: { return_url: 'https://localhost:6001/from-query' },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const configReturnUrl = 'https://localhost:6001/from-config';
      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl: configReturnUrl });
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(configReturnUrl)}`
      );
    });

    test('Return URL with its own query string stays encoded inside state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = 'https://localhost:6001/settings?tab=billing&x=1';
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });
      const params = new URL(location).searchParams;
      expect(params.get('client_id')).toBe(CLIENT_ID);
      expect(params.get('state')).toBe(returnUrl);
      expect(params.has('tab')).toBe(false);
      expect(params.has('x')).toBe(false);
    });

    test('Return URL at the max state length is passed as state', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const prefix = 'https://localhost:6001/';
      const returnUrl = `${prefix}${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH - prefix.length)}`;
      expect(returnUrl.length).toBe(STATE_PARAM_MAX_CHAR_LENGTH);

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
    });

    test('Return URL over the max state length is dropped', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const prefix = 'https://localhost:6001/';
      const returnUrl = `${prefix}${'a'.repeat(STATE_PARAM_MAX_CHAR_LENGTH - prefix.length + 1)}`;
      expect(returnUrl.length).toBe(STATE_PARAM_MAX_CHAR_LENGTH + 1);

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Empty LoginConfig returnUrl and no return_url query param (no state)', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl: '' });
      expect(location).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);

      // App-level authorization requests are not enabled, so the login state cookie is never touched.
      expect(mockRes.getHeader('Set-Cookie')).toBeUndefined();
    });

    test('Custom application login URL redirect', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://google.com?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain with return_url query param passes state', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = `https://${parseTenantFromRootDomain}/settings`;
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
        query: { return_url: returnUrl },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      expect(location).toBe(
        `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`
      );
      expect(mockRes.getHeader('Set-Cookie')).toBeUndefined();
    });

    test('Custom application login URL with return URL passes state', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const returnUrl = `https://${parseTenantFromRootDomain}/settings`;
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const location: string = await wristbandAuth.pagesRouter.login(mockReq, mockRes, { returnUrl });
      expect(location).toBe(`https://google.com?client_id=${CLIENT_ID}&state=${encodeURIComponent(returnUrl)}`);
    });
  });
});
