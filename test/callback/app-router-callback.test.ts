import { createMocks } from 'node-mocks-http';
import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { encryptLoginState, LOGIN_STATE_COOKIE_SEPARATOR } from '../helpers/login-state';
import { LoginState, AppRouterCallbackResult, CallbackData } from '../../src/types';
import { createMockNextRequest, parseSetCookies } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const APP_HOME_URL = 'https://myapp.com/home';

type ResolveRedirectUrl = Parameters<WristbandAuth['appRouter']['callback']>[1];

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
  // Off-site returnUrl is rejected by open redirect validation.
  expect(callbackData.returnUrl).toBeUndefined();
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
      // Tenant custom domain validation now runs during login/callback/logout.
      if (url.includes('/api/v1/custom-domains/validate')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          text: jest.fn().mockResolvedValue(JSON.stringify({ valid: true })),
        });
      }
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });

      // First verify result and data
      const { callbackData, response, type, reason } = callbackResult;
      expect(type).toBe('completed');
      expect(reason).toBeUndefined();
      expect(callbackData).toBeTruthy();

      if (callbackData) {
        validateMockCallbackData(callbackData);
      }

      // Now verify the response
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
      expect(loginStateCookie.domain).toBeUndefined();
      expect(loginStateCookie.path).toBe('/');
      expect(loginStateCookie.samesite).toBe('Lax');
      expect(loginStateCookie.secure).toBe(true);

      const cookieValue: string = loginStateCookie.value;
      expect(cookieValue).toBeFalsy();
    });

    test('tokenExpirationBuffer explicitly disabled via 0', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        wristbandApplicationVanityDomain,
        tokenExpirationBuffer: 0,
        autoConfigureEnabled: false,
      });

      // Mock login state
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri,
        state: 'state',
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // Create mock request
      const { req } = createMocks({
        method: 'GET',
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });

      // With the buffer explicitly disabled, expiresIn should equal the raw token response value,
      // not the default-buffered value (1740) asserted in validateMockCallbackData().
      expect(callbackResult.type).toBe('completed');
      expect(callbackResult.callbackData?.expiresIn).toBe(mockTokens.expires_in);
    });

    describe('Tenant Subdomains Configuration', () => {
      test('Tenant Subdomains Configuration using tenant_name', async () => {
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
        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type, reason } = callbackResult;
        expect(type).toBe('completed');
        expect(reason).toBeUndefined();
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }

        // Now verify the response
        const { headers, status } = response;
        const locationUrl: string = headers.get('location')!;
        expect(status).toBe(302);
        expect(locationUrl).toBe(APP_HOME_URL);

        // The app-level authorization requests flag is not enabled, so the cleared cookie is host-only
        const parsedCookies = parseSetCookies(response.headers.getSetCookie());
        expect(parsedCookies).toHaveLength(1);
        expect(parsedCookies[0].domain).toBeUndefined();
      });
    });

    describe('Custom Domains and Tenant Subdomains', () => {
      test('Custom Domains and Tenant Subdomains Configuration using tenant_name', async () => {
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
        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type, reason } = callbackResult;
        expect(type).toBe('completed');
        expect(reason).toBeUndefined();
        expect(callbackData).toBeTruthy();
        if (callbackData) {
          expect(callbackData.tenantName).toBe('devs4you');
          expect(callbackData.customState).toBeFalsy();
          expect(callbackData.returnUrl).toBeFalsy();
        }

        // Now verify the response
        const { headers, status } = response;
        const locationUrl: string = headers.get('location')!;
        expect(status).toBe(302);
        expect(locationUrl).toBe(APP_HOME_URL);

        // The app-level authorization requests flag is not enabled, so the cleared cookie is host-only
        const parsedCookies = parseSetCookies(response.headers.getSetCookie());
        expect(parsedCookies).toHaveLength(1);
        expect(parsedCookies[0].domain).toBeUndefined();
      });
    });
    describe('Return URL Validation', () => {
      const rootDomain = 'business.invotastic.com';

      // Runs a successful callback with the given returnUrl in the login state and returns the callback data.
      // With tenant subdomains, the tenant comes from the host; without, it comes from the tenant_name query param.
      async function runCallbackWithReturnUrl(
        returnUrl: string,
        useTenantSubdomains: boolean,
        applicationAuthorizationRequestsEnabled: boolean = false
      ): Promise<CallbackData | undefined> {
        const host = useTenantSubdomains ? `devs4you.${rootDomain}` : rootDomain;
        const callbackLoginUrl = useTenantSubdomains
          ? `https://{tenant_name}.${rootDomain}/api/auth/login`
          : `https://${rootDomain}/api/auth/login`;
        const callbackRedirectUri = useTenantSubdomains
          ? `https://{tenant_name}.${rootDomain}/api/auth/callback`
          : `https://${rootDomain}/api/auth/callback`;

        const authConfig = {
          clientId: CLIENT_ID,
          clientSecret: CLIENT_SECRET,
          loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
          loginUrl: callbackLoginUrl,
          redirectUri: callbackRedirectUri,
          applicationAuthorizationRequestsEnabled,
          wristbandApplicationVanityDomain,
          autoConfigureEnabled: false,
        };
        wristbandAuth = createWristbandAuth(authConfig);

        const loginState: LoginState = {
          codeVerifier: 'codeVerifier',
          redirectUri: callbackRedirectUri,
          state: 'state',
          returnUrl,
        };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        // Set x-forwarded-proto to match a real HTTPS request behind a proxy.
        const { req } = createMocks({
          method: 'GET',
          url: useTenantSubdomains
            ? `https://${host}/api/auth/callback?state=state&code=code`
            : `https://${host}/api/auth/callback?state=state&code=code&tenant_name=devs4you`,
          headers: {
            host,
            'x-forwarded-proto': 'https',
            cookie: `login#state#1234567890=${encryptedLoginState}`,
          },
        });
        const mockNextRequest = createMockNextRequest(req);

        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        expect(callbackResult.type).toBe('completed');
        return callbackResult.callbackData;
      }

      test('Allows a relative path returnUrl', async () => {
        const callbackData = await runCallbackWithReturnUrl('/settings?tab=billing', false);
        expect(callbackData?.returnUrl).toBe('/settings?tab=billing');
      });

      test('Allows an absolute returnUrl on the request host', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard`, false);
        expect(callbackData?.returnUrl).toBe(`https://${rootDomain}/dashboard`);
      });

      test('Rejects an off-site returnUrl', async () => {
        const callbackData = await runCallbackWithReturnUrl('https://evil.com/phish', false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Rejects a protocol-relative returnUrl to another host', async () => {
        const callbackData = await runCallbackWithReturnUrl('//evil.com/phish', false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Rejects a returnUrl with a mismatched protocol', async () => {
        const callbackData = await runCallbackWithReturnUrl(`http://${rootDomain}/dashboard`, false);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Allows a returnUrl on the current tenant subdomain', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://devs4you.${rootDomain}/dashboard`, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard`);
      });

      test('Rejects a returnUrl on a different tenant subdomain', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://other.${rootDomain}/dashboard`, true);
        expect(callbackData?.returnUrl).toBeUndefined();
      });

      test('Allows a root domain returnUrl unchanged when app-level authorization requests are disabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard`, true, false);
        expect(callbackData?.returnUrl).toBe(`https://${rootDomain}/dashboard`);
      });

      test('Rewrites a root domain returnUrl to the tenant subdomain when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://${rootDomain}/dashboard?x=1#top`, true, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard?x=1#top`);
      });

      test('Does not rewrite a returnUrl already on the tenant subdomain when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl(`https://devs4you.${rootDomain}/dashboard`, true, true);
        expect(callbackData?.returnUrl).toBe(`https://devs4you.${rootDomain}/dashboard`);
      });

      test('Does not rewrite a relative path when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl('/dashboard', true, true);
        expect(callbackData?.returnUrl).toBe('/dashboard');
      });

      test('Still rejects an off-site returnUrl when app-level authorization requests are enabled', async () => {
        const callbackData = await runCallbackWithReturnUrl('https://evil.com/phish', true, true);
        expect(callbackData?.returnUrl).toBeUndefined();
      });
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      // login state cookie is missing, which should redirect to app-level login.
      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });
      const { callbackData, response, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`
      );

      // No login state cookie exists, so none is cleared
      expect(response.headers.getSetCookie()).toHaveLength(0);
    });

    describe('Missing login state cookie', () => {
      test('Missing login state cookie, with tenant subdomains using tenant_name', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${redirectUri}?state=state&code=code`,
          headers: { host: `devs4you.${parseTenantFromRootDomain}` },
        });
        const mockNextRequest = createMockNextRequest(req);

        // login state cookie is missing, which should redirect to app-level login.
        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(callbackData).toBeFalsy();

        // Validate Redirect response
        expect(response.status).toBe(302);
        expect(response.headers.get('location')).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);

        // No login state cookie exists, so none is cleared
        expect(response.headers.getSetCookie()).toHaveLength(0);
      });
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you&error=login_required&error_description=Login required`,
        headers: {
          host: `devs4you.${parseTenantFromRootDomain}`,
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });
      const { callbackData, response, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`
      );

      // The login state cookie is cleared on the redirect response
      const parsedCookies = parseSetCookies(response.headers.getSetCookie());
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].name).toBe('login#state#1234567890');
      expect(parsedCookies[0]['max-age']).toBe('0');
    });

    describe('Login required error', () => {
      test('Tenant Subdomain Configuration for login_required error using tenant_name', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

        // Mock login state
        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${redirectUri}?state=state&code=code&tenant_name=devs4you&error=login_required&error_description=Login required`,
          headers: {
            host: `devs4you.${parseTenantFromRootDomain}`,
            cookie: `login#state#1234567890=${encryptedLoginState}`,
          },
        });
        const mockNextRequest = createMockNextRequest(req);

        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(callbackData).toBeFalsy();

        // Validate Redirect response
        expect(response.status).toBe(302);
        expect(response.headers.get('location')).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);

        // The login state cookie is cleared on the redirect response
        const parsedCookies = parseSetCookies(response.headers.getSetCookie());
        expect(parsedCookies).toHaveLength(1);
        expect(parsedCookies[0].name).toBe('login#state#1234567890');
        expect(parsedCookies[0]['max-age']).toBe('0');
      });
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });
      const { callbackData, response, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you`
      );

      // The login state cookie is cleared on the redirect response
      const parsedCookies = parseSetCookies(response.headers.getSetCookie());
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].name).toBe('login#state#1234567890');
      expect(parsedCookies[0]['max-age']).toBe('0');
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you&tenant_custom_domain=custom.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });
      const { callbackData, response, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you&tenant_custom_domain=custom.tenant.com`
      );

      // The login state cookie is cleared on the redirect response
      const parsedCookies = parseSetCookies(response.headers.getSetCookie());
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].name).toBe('login#state#1234567890');
      expect(parsedCookies[0]['max-age']).toBe('0');
    });

    describe('State mismatch', () => {
      test('Cookie login state not matching query param state, with tenant subdomains using tenant_name', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
        wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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

        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(callbackData).toBeFalsy();

        // Validate Redirect response
        expect(response.status).toBe(302);
        expect(response.headers.get('location')).toBe(`https://devs4you.${parseTenantFromRootDomain}/api/auth/login`);

        // The login state cookie is cleared on the redirect response
        const parsedCookies = parseSetCookies(response.headers.getSetCookie());
        expect(parsedCookies).toHaveLength(1);
        expect(parsedCookies[0].name).toBe('login#state#1234567890');
        expect(parsedCookies[0]['max-age']).toBe('0');
      });
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
        url: `${redirectUri}?state=state&code=code&tenant_name=devs4you&tenant_custom_domain=custom.tenant.com`,
        headers: { host: `${parseTenantFromRootDomain}`, cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      const mockNextRequest = createMockNextRequest(req);

      const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });
      const { callbackData, response, type } = callbackResult;
      expect(type).toBe('redirect_required');
      expect(callbackData).toBeFalsy();

      // Validate Redirect response
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(
        `https://${parseTenantFromRootDomain}/api/auth/login?tenant_name=devs4you&tenant_custom_domain=custom.tenant.com`
      );

      // The login state cookie is cleared on the redirect response
      const parsedCookies = parseSetCookies(response.headers.getSetCookie());
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].name).toBe('login#state#1234567890');
      expect(parsedCookies[0]['max-age']).toBe('0');
    });

    describe('State mismatch with custom domain', () => {
      test('Cookie login state not matching query param state, with custom domain, with tenant subdomains using tenant_name', async () => {
        parseTenantFromRootDomain = 'business.invotastic.com';
        loginUrl = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/login`;
        redirectUri = `https://{tenant_name}.${parseTenantFromRootDomain}/api/auth/callback`;
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
          applicationAuthorizationRequestsEnabled: false,
        });

        // Mock login state
        const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri: redirectUri, state: 'bad_state' };
        const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

        // Create mock request
        const { req } = createMocks({
          method: 'GET',
          url: `${redirectUri}?state=state&code=code&tenant_name=devs4you&tenant_custom_domain=custom.tenant.com`,
          headers: {
            host: `devs4you.${parseTenantFromRootDomain}`,
            cookie: `login#state#1234567890=${encryptedLoginState}`,
          },
        });
        const mockNextRequest = createMockNextRequest(req);

        const callbackResult: AppRouterCallbackResult = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return APP_HOME_URL;
        });
        const { callbackData, response, type } = callbackResult;
        expect(type).toBe('redirect_required');
        expect(callbackData).toBeFalsy();

        // Validate Redirect response
        expect(response.status).toBe(302);
        expect(response.headers.get('location')).toBe(
          `https://devs4you.${parseTenantFromRootDomain}/api/auth/login?tenant_custom_domain=custom.tenant.com`
        );

        // The login state cookie is cleared on the redirect response
        const parsedCookies = parseSetCookies(response.headers.getSetCookie());
        expect(parsedCookies).toHaveLength(1);
        expect(parsedCookies[0].name).toBe('login#state#1234567890');
        expect(parsedCookies[0]['max-age']).toBe('0');
      });
    });
  });

  describe('Redirect URL Resolution', () => {
    const rootDomain = 'business.invotastic.com';
    const host = `devs4you.${rootDomain}`;

    // Creates the SDK and a callback request with a valid login state cookie, with the tenant taken from the host.
    async function setupCallback(returnUrl?: string) {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_name}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_name}.${rootDomain}/api/auth/callback`,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });

      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: `https://{tenant_name}.${rootDomain}/api/auth/callback`,
        state: 'state',
        ...(returnUrl ? { returnUrl } : {}),
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // The request URL host is the server's own address, as Next.js reports it behind a proxy.
      const { req } = createMocks({
        method: 'GET',
        url: 'http://localhost:3000/api/auth/callback?state=state&code=code',
        headers: { host, 'x-forwarded-proto': 'https', cookie: `login#state#1234567890=${encryptedLoginState}` },
      });
      return createMockNextRequest(req);
    }

    test('Converts a relative path to an absolute URL using the host header', async () => {
      const mockNextRequest = await setupCallback();

      const { response, type } = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return '/dashboard';
      });

      expect(type).toBe('completed');
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(`https://${host}/dashboard`);
    });

    test('Converts a relative path to an absolute URL using X-Forwarded-Host behind a trusted proxy', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_name}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_name}.${rootDomain}/api/auth/callback`,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
        trustProxyHeaders: true,
      });

      const returnUrl = `https://${host}/settings`;
      const loginState: LoginState = {
        codeVerifier: 'codeVerifier',
        redirectUri: `https://{tenant_name}.${rootDomain}/api/auth/callback`,
        state: 'state',
        returnUrl,
      };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

      // The proxy forwards to an internal host, so the tenant subdomain is only in X-Forwarded-Host.
      const { req } = createMocks({
        method: 'GET',
        url: 'http://localhost:3000/api/auth/callback?state=state&code=code',
        headers: {
          host: 'internal-app:3000',
          'x-forwarded-host': host,
          'x-forwarded-proto': 'https',
          cookie: `login#state#1234567890=${encryptedLoginState}`,
        },
      });
      const mockNextRequest = createMockNextRequest(req);

      const { callbackData, response, type } = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return '/dashboard';
      });

      expect(type).toBe('completed');
      expect(callbackData?.tenantName).toBe('devs4you');
      // The returnUrl is validated against the forwarded host, so it is kept.
      expect(callbackData?.returnUrl).toBe(returnUrl);
      expect(response.status).toBe(302);
      expect(response.headers.get('location')).toBe(`https://${host}/dashboard`);
    });

    test('Supports an async resolver', async () => {
      const mockNextRequest = await setupCallback();

      const { response, type } = await wristbandAuth.appRouter.callback(mockNextRequest, async () => {
        return Promise.resolve(APP_HOME_URL);
      });

      expect(type).toBe('completed');
      expect(response.headers.get('location')).toBe(APP_HOME_URL);
    });

    test('Passes the request and callback data to the resolver', async () => {
      const mockNextRequest = await setupCallback();
      const resolveRedirectUrl = jest.fn().mockReturnValue(APP_HOME_URL);

      const { callbackData } = await wristbandAuth.appRouter.callback(mockNextRequest, resolveRedirectUrl);

      expect(resolveRedirectUrl).toHaveBeenCalledTimes(1);
      expect(resolveRedirectUrl).toHaveBeenCalledWith(mockNextRequest, callbackData);
    });

    test('Redirects to the validated returnUrl when the resolver returns it', async () => {
      const mockNextRequest = await setupCallback('/settings?tab=billing');

      const { response } = await wristbandAuth.appRouter.callback(mockNextRequest, (req, data) => {
        return data.returnUrl || APP_HOME_URL;
      });

      expect(response.headers.get('location')).toBe(`https://${host}/settings?tab=billing`);
    });

    test('Clears the login state cookie on the completed response', async () => {
      const mockNextRequest = await setupCallback();

      const { response } = await wristbandAuth.appRouter.callback(mockNextRequest, () => {
        return APP_HOME_URL;
      });

      const parsedCookies = parseSetCookies(response.headers.getSetCookie());
      expect(parsedCookies).toHaveLength(1);
      expect(parsedCookies[0].name).toBe('login#state#1234567890');
      expect(parsedCookies[0]['max-age']).toBe('0');
    });

    test('Throws when the resolver returns an empty string', async () => {
      const mockNextRequest = await setupCallback();

      await expect(
        wristbandAuth.appRouter.callback(mockNextRequest, () => {
          return '';
        })
      ).rejects.toThrow('resolveRedirectUrl must return a non-empty URL');
    });

    test('Throws before any Wristband API call when the resolver is missing', async () => {
      const mockNextRequest = await setupCallback();

      // Bypass the type check to simulate a JavaScript caller that omits the resolver.
      await expect(
        wristbandAuth.appRouter.callback(mockNextRequest, undefined as unknown as ResolveRedirectUrl)
      ).rejects.toThrow('resolveRedirectUrl must be a function');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('Throws before any Wristband API call when the resolver is not a function', async () => {
      const mockNextRequest = await setupCallback();

      // Bypass the type check to simulate passing a URL string instead of a function.
      await expect(
        wristbandAuth.appRouter.callback(mockNextRequest, APP_HOME_URL as unknown as ResolveRedirectUrl)
      ).rejects.toThrow('resolveRedirectUrl must be a function');
      expect(global.fetch).not.toHaveBeenCalled();
    });

    test('Does not call the resolver when a redirect to login is required', async () => {
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl: `https://{tenant_name}.${rootDomain}/api/auth/login`,
        redirectUri: `https://{tenant_name}.${rootDomain}/api/auth/callback`,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
        applicationAuthorizationRequestsEnabled: false,
      });
      const resolveRedirectUrl = jest.fn().mockReturnValue(APP_HOME_URL);

      // No login state cookie
      const { req } = createMocks({
        method: 'GET',
        url: 'http://localhost:3000/api/auth/callback?state=state&code=code',
        headers: { host, 'x-forwarded-proto': 'https' },
      });
      const mockNextRequest = createMockNextRequest(req);

      const { reason, type } = await wristbandAuth.appRouter.callback(mockNextRequest, resolveRedirectUrl);

      expect(type).toBe('redirect_required');
      expect(reason).toBe('missing_login_state');
      expect(resolveRedirectUrl).not.toHaveBeenCalled();
    });
  });
});
