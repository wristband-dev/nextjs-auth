/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable no-underscore-dangle */

import { createMocks, MockResponse } from 'node-mocks-http';

import { NextApiRequest, NextApiResponse } from 'next';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { decryptLoginState } from '../../src/utils/auth/common-utils';
import { LoginState } from '../../src/types';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const CUSTOM_SCOPES = ['openid', 'roles'];
const CUSTOM_STATE = { test: 'abc' };
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

function validateRedirectResponse(mockRes: MockResponse<NextApiResponse>, expectedOrigin: string) {
  const { statusCode } = mockRes;
  expect(statusCode).toEqual(302);
  const location: string = mockRes._getRedirectUrl();
  expect(location).toBeTruthy();
  const locationUrl: URL = new URL(location);
  const { pathname, origin } = locationUrl;
  expect(origin).toEqual(expectedOrigin);
  expect(pathname).toEqual('/api/v1/oauth2/authorize');
}

async function validateLoginStateCookie(mockRes: MockResponse<NextApiResponse>) {
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

  const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
  expect(loginState.state).toEqual(keyParts[1]);
  expect(loginState.customState).toBeUndefined();
}

describe('Custom Login Configurations', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationDomain: string;

  beforeEach(() => {
    rootDomain = 'business.invotastic.com';
    wristbandApplicationDomain = 'auth.invotastic.com';
    loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
    redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
  });

  describe('Successful Redirect to Authorize Endpoint', () => {
    test('Custom Scopes Configuration at the Class Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
        scopes: CUSTOM_SCOPES,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

      // Validate query params of Authorize URL
      expect(searchParams.get('scope')).toEqual(CUSTOM_SCOPES.join(' '));

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
      expect(loginStateCookie.secure).toBe(true);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeTruthy();
      const loginState: LoginState = await decryptLoginState(cookieValue, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(searchParams.get('state')).toEqual(keyParts[1]);
      expect(loginState.codeVerifier).toBeTruthy();
      expect(loginState.redirectUri).toBe(redirectUri);
      expect(loginState.customState).toBeFalsy();
      expect(loginState.returnUrl).toBeUndefined();
    });

    test('Custom State at the Function Level', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { customState: CUSTOM_STATE });

      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${wristbandApplicationDomain}`);
      expect(pathname).toEqual('/api/v1/oauth2/authorize');

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
      expect(loginStateCookie.secure).toBe(true);

      const loginState: LoginState = await decryptLoginState(loginStateCookie.value, LOGIN_STATE_COOKIE_SECRET);
      expect(loginState.state).toEqual(keyParts[1]);
      expect(loginState.customState).toEqual(CUSTOM_STATE);
    });

    // ///////////////////////////////////////////
    //  PRIORITY ORDER #1 - TENANT CUSTOM DOMAIN
    // ///////////////////////////////////////////

    test('01: Tenant custom domain query param precedence over tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    test('02: Tenant custom domain query param precedence over tenant domain query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        useCustomDomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com', tenant_domain: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    test('03: Tenant custom domain query param precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'tenant.custom.com',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    test('04: Tenant custom domain query param precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { tenant_custom_domain: 'query.tenant.com' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, {
        defaultTenantDomainName: 'tenant',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, 'https://query.tenant.com');
      await validateLoginStateCookie(mockRes);
    });

    // ///////////////////////////////////////
    //  PRIORITY ORDER #2 - TENANT SUBDOMAIN
    // ///////////////////////////////////////

    test('01: Tenant subdomain takes precedence over tenant domain query param', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { tenant_domain: 'query' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes);

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    test('02: Tenant subdomain takes precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantCustomDomain: 'default.tenant.com' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    test('03: Tenant subdomain takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantDomainName: 'default' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    // ////////////////////////////////////////////////
    //  PRIORITY ORDER #3 - TENANT DOMAIN QUERY PARAM
    // ////////////////////////////////////////////////

    test('01: Tenant domain query param takes precedence over default tenant custom domain Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantCustomDomain: 'global.tenant.com' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    test('02: Tenant domain query param takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { tenant_domain: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantDomainName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://devs4you.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #4 - DEFAULT TENANT CUSTOM DOMAIN CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant custom domain takes precedence over default tenant domain name Login config', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
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
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, {
        defaultTenantDomainName: 'global',
        defaultTenantCustomDomain: 'global.tenant.com',
      });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://global.tenant.com`);
      await validateLoginStateCookie(mockRes);
    });

    test('02: Default tenant custom domain without any other Login config or query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantCustomDomain: 'tenant.custom.com' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://tenant.custom.com`);
      await validateLoginStateCookie(mockRes);
    });

    // //////////////////////////////////////////////////////////
    //  PRIORITY ORDER #5 - DEFAULT TENANT DOMAIN NAME CONFIG
    // //////////////////////////////////////////////////////////

    test('01: Default tenant domain name without any other Login config or query params', async () => {
      rootDomain = 'business.invotastic.com';
      wristbandApplicationDomain = 'auth.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://${rootDomain}/api/auth/login`,
        redirectUri: `https://${rootDomain}/api/auth/callback`,
        rootDomain,
        useCustomDomains: true,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      await wristbandAuth.pageRouter.login(mockReq, mockRes, { defaultTenantDomainName: 'global' });

      // Validate Redirect response
      validateRedirectResponse(mockRes, `https://global.${wristbandApplicationDomain}`);
      await validateLoginStateCookie(mockRes);
    });
  });
});
