/* eslint-disable no-underscore-dangle */

import { createMocks, MockResponse } from 'node-mocks-http';
import { NextApiRequest, NextApiResponse } from 'next';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { encryptLoginState } from '../../src/utils/auth/common-utils';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { LoginState, CallbackResultType, PageRouterCallbackResult, CallbackData } from '../../src/types';
import { parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';

const mockTokens = {
  access_token: 'accessToken',
  expires_in: 1800,
  id_token: 'idToken',
  refresh_token: 'refreshToken',
  token_type: 'bearer',
};
const mockUserinfo = {
  sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
  tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
  app_id: 'dy42gabu5jebreq6jajskk2n34',
  idp_name: 'wristband',
  email: 'test@wristband.dev',
  email_verified: true,
};

function validateMockCallbackData(callbackData: CallbackData) {
  expect(callbackData.accessToken).toBe('accessToken');
  expect(callbackData.expiresIn).toBe(1800);
  expect(callbackData.idToken).toBe('idToken');
  expect(callbackData.refreshToken).toBe('refreshToken');
  expect(callbackData.customState).toEqual({ test: 'abc' });
  expect(callbackData.returnUrl).toBe('https://reddit.com');
  expect(callbackData.tenantDomainName).toBe('devs4you');
  expect(callbackData.userinfo).toBeTruthy();
  expect(callbackData.userinfo.sub).toBe('5q6j4qe2cva3dm3cbdvjoxvuze');
  expect(callbackData.userinfo.tnt_id).toBe('fr2vishnqjdvfbcijxa3a4adhe');
  expect(callbackData.userinfo.app_id).toBe('dy42gabu5jebreq6jajskk2n34');
  expect(callbackData.userinfo.idp_name).toBe('wristband');
  expect(callbackData.userinfo.email).toBe('test@wristband.dev');
  expect(callbackData.userinfo.email_verified).toBe(true);
}

describe('Multi Tenant Callback - Page Router', () => {
  let wristbandAuth: WristbandAuth;
  let rootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationDomain: string;

  beforeEach(() => {
    rootDomain = 'localhost:6001';
    loginUrl = `https://${rootDomain}/api/auth/login`;
    redirectUri = `https://${rootDomain}/api/auth/callback`;
    wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

    // Reset fetch mock before each test
    global.fetch = jest.fn();
    global.fetch = jest.fn().mockImplementation((url: string) => {
      if (url.endsWith('/api/v1/oauth2/token')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockTokens)),
        });
      }
      if (url.endsWith('/api/v1/oauth2/userinfo')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockUserinfo)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });
  });

  describe('Callback Happy Path', () => {
    test('Default Configuration', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri,
        state: 'state',
        customState: { test: 'abc' },
        returnUrl: 'https://reddit.com',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you`,
        headers: { host: `${rootDomain}` },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);

      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.COMPLETED);
      expect(callbackData).toBeTruthy();

      if (callbackData) {
        validateMockCallbackData(callbackData);
      }

      // Validate no-cache headers
      expect(mockRes.getHeader('Cache-Control')).toBe('no-store');
      expect(mockRes.getHeader('Pragma')).toBe('no-cache');

      // Validate login state cookie is getting cleared
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
      expect(loginStateCookie['max-age']).toBe('0');
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBe(true);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeFalsy();
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
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Validate callback data contents
      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.COMPLETED);
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantDomainName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }
      // Validate response is not redirecting the user
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeFalsy();
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
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
      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // Validate callback data contents
      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.COMPLETED);
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantDomainName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }
      // Validate response is not redirecting the user
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeFalsy();
    });
  });

  describe('Redirect to Tenant-level Login', () => {
    test('Missing login state cookie, without tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { state: 'state', code: 'code', tenant_domain: 'devs4you' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // login state cookie is missing, which should redirect to app-level login.
      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBe(`https://${rootDomain}/api/auth/login?tenant_domain=devs4you`);
    });

    test('Missing login state cookie, with tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      // login state cookie is missing, which should redirect to app-level login.
      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Default Configuration for login_required error', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        query: {
          state: 'state',
          code: 'code',
          tenant_domain: 'devs4you',
          error: 'login_required',
          error_description: 'Login required',
        },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
      expect(searchParams.get('tenant_domain')).toBe('devs4you');
    });

    test('Tenant Subdomain Configuration for login_required error', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code', error: 'login_required', error_description: 'Login required' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Cookie login state not matching query param state, without subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        query: { state: 'state', code: 'code', tenant_domain: 'devs4you' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin, searchParams } = locationUrl;
      expect(origin).toEqual(`https://${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
      expect(searchParams.get('tenant_domain')).toBe('devs4you');
    });

    test('Cookie login state not matching query param state, with tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toBeTruthy();
      const locationUrl: URL = new URL(location);
      const { pathname, origin } = locationUrl;
      expect(origin).toEqual(`https://devs4you.${rootDomain}`);
      expect(pathname).toEqual('/api/auth/login');
    });

    test('Cookie login state not matching query param state, with custom domain, without tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://${rootDomain}/api/auth/login`;
      redirectUri = `https://${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `${rootDomain}` },
        query: { state: 'state', code: 'code', tenant_domain: 'devs4you', tenant_custom_domain: 'custom.tenant.com' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toEqual(
        `https://${rootDomain}/api/auth/login?tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`
      );
    });

    test('Cookie login state not matching query param state, with custom domain, with tenant subdomains', async () => {
      rootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req, res } = createMocks({
        method: 'GET',
        headers: { host: `devs4you.${rootDomain}` },
        query: { state: 'state', code: 'code', tenant_domain: 'devs4you', tenant_custom_domain: 'custom.tenant.com' },
        cookies: { 'login#state#1234567890': encryptedLoginState },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      const callbackResult: PageRouterCallbackResult = await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      const { callbackData, result } = callbackResult;
      expect(result).toBe(CallbackResultType.REDIRECT_REQUIRED);
      expect(callbackData).toBeFalsy();
      // Validate Redirect response
      const { statusCode } = mockRes;
      expect(statusCode).toEqual(302);
      const location: string = mockRes._getRedirectUrl();
      expect(location).toEqual(`https://devs4you.${rootDomain}/api/auth/login?tenant_custom_domain=custom.tenant.com`);
    });
  });
});
