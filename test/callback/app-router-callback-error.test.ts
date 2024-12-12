/* eslint-disable no-underscore-dangle */
/* eslint-disable import/no-extraneous-dependencies */

import httpMocks, { createMocks } from 'node-mocks-http';

import { LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils/auth/common-utils';
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
      wristbandApplicationDomain: WRISTBAND_APPLICATION_DOMAIN,
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
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
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.getError()).toBe('BAD');
      expect(error.getErrorDescription()).toBe('bad');
    }
  });

  describe('Redirect to Application-level Login', () => {
    test('Missing login state cookie, without subdomains, without tenant domain query param', async () => {
      const rootDomain = 'business.invotastic.com';
      const loginUrl = `https://${rootDomain}/api/auth/login`;
      const redirectUri = `https://${rootDomain}/api/auth/callback`;
      const wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        useTenantSubdomains: false,
        wristbandApplicationDomain,
      });

      // Create mock request
      const req = httpMocks.createRequest({
        url: `${REDIRECT_URI}?state=state&code=code`,
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.callback(mockNextRequest);
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.getError()).toBe('missing_tenant_domain');
        expect(error.getErrorDescription()).toBe(
          'Callback request is missing the [tenant_domain] query parameter from Wristband'
        );
      }
    });

    test('Missing login state cookie, with subdomains, and without URL subdomain', async () => {
      const rootDomain = 'business.invotastic.com';
      const loginUrl = `https://{tenant_domain}.${rootDomain}/api/auth/login`;
      const redirectUri = `https://{tenant_domain}.${rootDomain}/api/auth/callback`;
      const wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
      wristbandAuth = createWristbandAuth({
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        customApplicationLoginPageUrl: 'https://google.com',
        loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
        loginUrl,
        redirectUri,
        rootDomain,
        useTenantSubdomains: true,
        wristbandApplicationDomain,
      });

      // Create mock request
      const req = httpMocks.createRequest({
        method: 'GET',
        url: `${REDIRECT_URI}?state=state&code=code`,
        headers: { host: rootDomain },
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.callback(mockNextRequest);
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.getError()).toBe('missing_tenant_subdomain');
        expect(error.getErrorDescription()).toBe('Callback request URL is missing a tenant subdomain');
      }
    });

    test('Create callback response, empty redirectURL', async () => {
      const rootDomain = 'business.invotastic.com';
      const loginUrl = `https://${rootDomain}/api/auth/login`;
      const redirectUri = `https://${rootDomain}/api/auth/callback`;
      const wristbandApplicationDomain = 'invotasticb2b-invotastic.dev.wristband.dev';
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
      const { req } = createMocks({
        method: 'GET',
        headers: { host: rootDomain },
        url: `${REDIRECT_URI}?tenant_domain=error`,
      });
      const mockNextRequest = createMockNextRequest(req);

      try {
        await wristbandAuth.appRouter.createCallbackResponse(mockNextRequest, '');
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof TypeError).toBe(true);
        expect(error.message).toBe('redirectUrl cannot be null or empty');
      }
    });
  });
});
