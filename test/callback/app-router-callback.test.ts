import { createMocks } from 'node-mocks-http';
import { NextResponse } from 'next/server';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { encryptLoginState } from '../../src/utils/crypto';
import { LOGIN_STATE_COOKIE_SEPARATOR } from '../../src/utils/constants';
import { LoginState, CallbackResult, CallbackData } from '../../src/types';
import { createMockNextRequest, parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const APP_HOME_URL = 'https://myapp.com/home';

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
  expect(callbackData.expiresIn).toBe(1740);
  expect(callbackData.idToken).toBe('idToken');
  expect(callbackData.refreshToken).toBe('refreshToken');
  expect(callbackData.customState).toEqual({ test: 'abc' });
  expect(callbackData.returnUrl).toBe('https://reddit.com');
  expect(callbackData.tenantName).toBe('devs4you');
  expect(callbackData.userinfo).toBeTruthy();
  expect(callbackData.userinfo.userId).toBe('5q6j4qe2cva3dm3cbdvjoxvuze');
  expect(callbackData.userinfo.tenantId).toBe('fr2vishnqjdvfbcijxa3a4adhe');
  expect(callbackData.userinfo.applicationId).toBe('dy42gabu5jebreq6jajskk2n34');
  expect(callbackData.userinfo.identityProviderName).toBe('wristband');
  expect(callbackData.userinfo.email).toBe('test@wristband.dev');
  expect(callbackData.userinfo.emailVerified).toBe(true);
}

describe('Multi Tenant Callback - App Router', () => {
  let wristbandAuth: WristbandAuth;
  let parseTenantFromRootDomain: string;
  let loginUrl: string;
  let redirectUri: string;
  let wristbandApplicationVanityDomain: string;

  beforeEach(() => {
    parseTenantFromRootDomain = 'localhost:6001';
    loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
    redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
    wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';

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
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
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
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);

      // First verify result and data
      const { callbackData, type, reason } = callbackResult;
      expect(type).toBe('completed');
      expect(reason).toBeUndefined();
      expect(callbackData).toBeTruthy();

      if (callbackData) {
        validateMockCallbackData(callbackData);
      }

      // Now verify the response
      const response: NextResponse = await wristbandAuth.appRouter.createCallbackResponse(
        mockNextRequest,
        APP_HOME_URL
      );

      const { headers, status } = response;
      const locationUrl: string = headers.get('location')!;
      expect(status).toBe(302);
      expect(locationUrl).toEqual(APP_HOME_URL);

      // Validate no-cache headers
      expect(headers.get('Cache-Control')).toBe('no-store');
      expect(headers.get('Pragma')).toBe('no-cache');

      // Validate login state cookie
      const setCookieHeaders = response.headers.getSetCookie();
      expect(setCookieHeaders).toBeTruthy();
      expect(setCookieHeaders).toHaveLength(1);
      const parsedCookies = parseSetCookies(setCookieHeaders);
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
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      // Validate callback data contents
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, type, reason } = callbackResult;
      expect(type).toBe('completed');
      expect(reason).toBeUndefined();
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }

      // Now verify the response
      const response: NextResponse = await wristbandAuth.appRouter.createCallbackResponse(
        mockNextRequest,
        APP_HOME_URL
      );
      const { headers, status } = response;
      const locationUrl: string = headers.get('location')!;
      expect(status).toBe(302);
      expect(locationUrl).toBe(APP_HOME_URL);
    });

    test('Custom Domains and Tenant Subdomains Configuration', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      wristbandApplicationVanityDomain = 'auth.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });
      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      // Validate callback data contents
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, type, reason } = callbackResult;
      expect(type).toBe('completed');
      expect(reason).toBeUndefined();
      expect(callbackData).toBeTruthy();
      if (callbackData) {
        expect(callbackData.tenantName).toBe('devs4you');
        expect(callbackData.customState).toBeFalsy();
        expect(callbackData.returnUrl).toBeFalsy();
      }

      // Now verify the response
      const response: NextResponse = await wristbandAuth.appRouter.createCallbackResponse(
        mockNextRequest,
        APP_HOME_URL
      );
      const { headers, status } = response;
      const locationUrl: string = headers.get('location')!;
      expect(status).toBe(302);
      expect(locationUrl).toBe(APP_HOME_URL);
    });
  });

  describe('Redirect to Tenant-level Login', () => {
    test('Missing login state cookie, without tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // login state cookie is missing, which should redirect to app-level login.
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_domain=devs4you`);
    });

    test('Missing login state cookie, with tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code`,
        headers: { host: `devs4you.${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // login state cookie is missing, which should redirect to app-level login.
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
    });

    test('Default Configuration for login_required error', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you&error=login_required&error_description=Login required`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_domain=devs4you`);
    });

    test('Tenant Subdomain Configuration for login_required error', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you&error=login_required&error_description=Login required`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
    });

    test('Cookie login state not matching query param state, without subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://${parseTenantFromRootDomain}/api/auth/login?tenant_domain=devs4you`);
    });

    test('Cookie login state not matching query param state, without subdomains, with tenant custom domain', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`
      );
    });

    test('Cookie login state not matching query param state, with tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
    });

    test('Cookie login state not matching query param state, with tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);
    });

    test('Cookie login state not matching query param state, with custom domain, without tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`
      );
    });

    test('Cookie login state not matching query param state, with custom domain, with tenant subdomains', async () => {
      parseTenantFromRootDomain = 'business.invotastic.com';
      loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        isApplicationCustomDomainActive: true,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_domain=devs4you&tenant_custom_domain=custom.tenant.com`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest);
      const { callbackData, redirectUrl, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(redirectUrl).toBe(
        `https://devs4you.${parseTenantFromRootDomain}/api/auth/login?tenant_custom_domain=custom.tenant.com`
      );
    });
  });
});
