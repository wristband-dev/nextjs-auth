/* eslint-disable no-underscore-dangle */

import type { NextApiRequest, NextApiResponse } from 'next';
import { createMocks, MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, LOGIN_STATE_COOKIE_SECRET, parseSetCookies } from '../test-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { LoginState } from '../../src/types';
import { decryptLoginState, encryptLoginState } from '../../src/utils/auth/common-utils';

function validateRedirectResponse(
  mockRes: MockResponse<NextApiResponse>,
  authorizeUrl: string,
  exprectedOrigin: string,
  expectedRedirectUri: string
) {
  expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
  expect(mockRes.getHeader('Pragma')).toBe('no-cache');

  const url: URL = new URL(authorizeUrl);
  const { pathname, origin, searchParams } = url;
  expect(origin).toEqual(exprectedOrigin);
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
  expect(loginStateCookie.samesite).toBe('lax');
  expect(loginStateCookie.secure).toBe(true);

  const cookieValue: string = loginStateCookie.value;
  expect(cookieValue).toBeTruthy();
  const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
  expect(loginState.state).toEqual(keyParts[1]);
  expect(searchParams.get('state')).toEqual(keyParts[1]);
  expect(loginState.codeVerifier).toBeTruthy();
  expect(loginState.redirectUri).toBe(expectedRedirectUri);
  expect(loginState.customState).toBeUndefined();
  expect(loginState.returnUrl).toBeUndefined();
}

describe('pageRouter.login()', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
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
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_domain=devs4you`,
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Call login with the mock request and response
      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate location header
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
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
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}?tenant_domain=devs4you`,
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Call login with the mock request and response
      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

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
      expect(loginStateCookie.samesite).toBe('lax');
      expect(loginStateCookie.secure).toBeUndefined();

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeUndefined();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you-${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(
        mockRes,
        authorizeUrl,
        `https://devs4you.${wristbandApplicationVanityDomain}`,
        redirectUri
      );
      validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains with Tenant Custom Domain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'tenant.custom.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, authorizeUrl, `https://tenant.custom.com`, redirectUri);
      validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('Custom Domains with All Domain Params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationVanityDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you', tenant_custom_domain: 'tenant.custom.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, authorizeUrl, `https://tenant.custom.com`, redirectUri);
      validateLoginStateCookie(mockRes, authorizeUrl, redirectUri);
    });

    test('With login_hint and return_url query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: `devs4you.${rootDomain}` },
        query: {
          login_hint: 'test@wristband.dev',
          return_url: `https://devs4you.${rootDomain}/settings`,
        },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      const locationUrl: URL = new URL(authorizeUrl);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationVanityDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('login_hint')).toBe('test@wristband.dev');

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
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.returnUrl).toBe(`https://devs4you.${rootDomain}/settings`);
    });

    test('Clear old login state cookie', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
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
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);

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

      // Validate new login state cookie
      const loginStateCookie = parsedCookies[1];
      const cookieKey: string = loginStateCookie.name;
      expect(cookieKey).toBeTruthy();
      const keyParts: string[] = cookieKey.split(LOGIN_STATE_COOKIE_SEPARATOR);
      expect(keyParts).toHaveLength(3);
      expect(keyParts[0]).toEqual('login');
      expect(keyParts[1]).toBeTruthy();
      expect(parseInt(keyParts[2], 10)).toBeGreaterThan(0);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
    });
  });

  describe('Redirect to Application-level Login/Tenant Discovery', () => {
    test('Unresolved tenant_domain and tenant_custom_domain query params', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
      });

      // tenant_domain and tenant_custom_domain query param is missing, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Unresolved tenant subdomain', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
    });

    test('Custom application login URL redirect', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;

      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationVanityDomain,
        customApplicationLoginPageUrl: 'https://google.com',
      });

      // Subdomain is missing from host, which should redirect to app-level login.
      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${loginUrl}`,
        headers: { host: rootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const authorizeUrl = await wristbandAuth.pageRouter.login(mockReq, mockRes);
      expect(authorizeUrl).toBe(`https://google.com?client_id=${CLIENT_ID}`);
    });
  });
});
