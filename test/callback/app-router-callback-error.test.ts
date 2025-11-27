/* eslint-disable no-underscore-dangle */
/* eslint-disable import/no-extraneous-dependencies */

import httpMocks, { createMocks } from 'node-mocks-http';

import { LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils/crypto';
import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src/index';
import { createMockNextRequest } from '../test-utils';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const LOGIN_URL = 'http://localhost:6001/api/auth/login';
const REDIRECT_URI = 'http://localhost:6001/api/auth/callback';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

describe('Callback Errors', () => {
  let wristbandAuth: WristbandAuth;

  beforeEach(() => {
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl: LOGIN_URL,
      redirectUri: REDIRECT_URI,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
    });
    // Reset fetch mock before each test
    global.fetch = jest.fn();
  });

  test('Invalid state query param', async () => {
    // Create mock request
    let { req } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}?code=code&tenant_domain=devs4you`,
    });
    let mockNextRequest = createMockNextRequest(req);

    // Missing state query parameter should throw an error
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }

    req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?code=code&tenant_domain=devs4you&state=1&state=2`,
    });
    mockNextRequest = createMockNextRequest(req);

    // Multiple state query parameters should throw an error
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }
  });

  test('Invalid code query param', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Create mock request
    let { req } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}?state=state&tenant_domain=devs4you`,
      headers: { cookie: `login#state#1234567890=${encryptedLoginState}` },
    });
    let mockNextRequest = createMockNextRequest(req);

    // Missing code query parameter should throw an error for happy path scenarios.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }

    req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_domain=devs4you&code=a&code=b`,
      headers: { cookie: `login#state#1234567890=blah` },
    });
    mockNextRequest = createMockNextRequest(req);
    // Multiple code query parameters should throw an error.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }
  });

  test('Invalid error query param', async () => {
    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_domain=devs4you&error=a&error=b`,
      headers: { cookie: `login#state#1234567890=blah` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error] passed from Wristband during callback');
    }
  });

  test('Invalid error_description query param', async () => {
    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_domain=devs4you&error_description=a&error_description=b`,
      headers: { cookie: `login#state#1234567890=blah` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Multiple error_description query parameters should throw an error.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error_description] passed from Wristband during callback');
    }
  });

  test('Invalid tenant_domain query param', async () => {
    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_domain=a&tenant_domain=b&code=code`,
      headers: { cookie: `login#state#1234567890=blah` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was encountered');
    }
  });

  test('Invalid tenant_custom_domain query param', async () => {
    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_custom_domain=a&tenant_custom_domain=b&code=code`,
      headers: { cookie: `login#state#1234567890=blah` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe(
        'Invalid query parameter [tenant_custom_domain] passed from Wristband during callback'
      );
    }
  });

  test('Error query parameter throws WristbandError', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&tenant_domain=devs4you&error=BAD&error_description=bad`,
      headers: { cookie: `login#state#1234567890=${encryptedLoginState}` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Only some errors are handled automatically by the SDK. All others will throw a WristbandError.
    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.code).toBe('BAD');
      expect(error.errorDescription).toBe('bad');
    }
  });

  test('InvalidGrantError during token exchange redirects to login', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&code=invalid_code&tenant_domain=devs4you`,
      headers: { cookie: `login#state#state=${encryptedLoginState}` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Mock fetch to return invalid_grant error
    const mockError = {
      error: 'invalid_grant',
      error_description: 'Authorization code is invalid or expired',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 400,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    const result = await wristbandAuth.appRouter.callback(mockNextRequest);

    expect(result.type).toBe('REDIRECT_REQUIRED');
    expect(result.redirectUrl).toBe(`${LOGIN_URL}?tenant_domain=devs4you`);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  test('Non-InvalidGrantError during token exchange is re-thrown', async () => {
    // Mock login state
    const loginState: LoginState = {
      codeVerifier: 'codeVerifier',
      redirectUri: REDIRECT_URI,
      state: 'state',
    };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);

    // Create mock request
    const req = httpMocks.createRequest({
      url: `${REDIRECT_URI}?state=state&code=code&tenant_domain=devs4you`,
      headers: { cookie: `login#state#state=${encryptedLoginState}` },
    });
    const mockNextRequest = createMockNextRequest(req);

    // Mock fetch to return a different error (not invalid_grant)
    const mockError = {
      error: 'server_error',
      error_description: 'Internal server error',
    };

    (global.fetch as jest.Mock).mockImplementationOnce((url: string) => {
      if (url === `https://${WRISTBAND_APPLICATION_DOMAIN}/api/v1/oauth2/token`) {
        return Promise.resolve({
          ok: false,
          status: 500,
          text: jest.fn().mockResolvedValueOnce(JSON.stringify(mockError)),
        });
      }
      return Promise.reject(new Error('Unexpected URL'));
    });

    try {
      await wristbandAuth.appRouter.callback(mockNextRequest);
      fail('Expected error to be thrown');
    } catch (error: any) {
      expect(error).toBeInstanceOf(WristbandError);
      const typedError = error as WristbandError;
      expect(typedError.code).toBe('unexpected_error');
      expect(typedError.errorDescription).toBe('Unexpected error');
      expect(typedError.originalError).toBeDefined();
    }

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  describe('Redirect to Application-level Login', () => {
    test('Missing login state cookie, without subdomains, without tenant domain query param', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
      const req = httpMocks.createRequest({
        url: `${REDIRECT_URI}?state=state&code=code`,
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.callback(mockNextRequest);
        fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.code).toBe('missing_tenant_domain');
        expect(error.errorDescription).toBe(
          'Callback request is missing the [tenant_domain] query parameter from Wristband'
        );
      }
    });

    test('Missing login state cookie, with subdomains, and without URL subdomain', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_domain}.${parseTenantFromRootDomain}/api/auth/callback`;
      const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        customApplicationLoginPageUrl: 'https://google.com',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        parseTenantFromRootDomain,
        wristbandApplicationVanityDomain,
        autoConfigureEnabled: false,
      });

      // Create mock request
      const req = httpMocks.createRequest({
        method: 'GET',
        url: `${REDIRECT_URI}?state=state&code=code`,
        headers: { host: parseTenantFromRootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.callback(mockNextRequest);
        fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.code).toBe('missing_tenant_subdomain');
        expect(error.errorDescription).toBe('Callback request URL is missing a tenant subdomain');
      }
    });

    test('Create callback response, empty redirectURL', async () => {
      const parseTenantFromRootDomain = 'business.invotastic.com';
      const loginUrl = `https://${parseTenantFromRootDomain}/api/auth/login`;
      const redirectUri = `https://${parseTenantFromRootDomain}/api/auth/callback`;
      const wristbandApplicationVanityDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
        headers: { host: parseTenantFromRootDomain },
        url: `${REDIRECT_URI}?tenant_domain=error`,
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, '');
        fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof TypeError).toBe(true);
        expect(error.message).toBe('redirectUrl cannot be null or empty');
      }
    });
  });
});
