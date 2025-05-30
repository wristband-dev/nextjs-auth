/* eslint-disable no-underscore-dangle */
/* eslint-disable import/no-extraneous-dependencies */

import httpMocks, { createMocks, MockResponse } from 'node-mocks-http';

import { NextApiRequest, NextApiResponse } from 'next';
import { LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils/auth/common-utils';
import { createWristbandAuth, WristbandAuth, WristbandError } from '../../src/index';

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
    });
    // Reset fetch mock before each test
    global.fetch = jest.fn();
  });

  test('Invalid state query param', async () => {
    // Create mock request and response
    let { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { code: 'code', tenant_domain: 'devs4you' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    let mockReq = req as unknown as NextApiRequest;
    let mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Missing state query parameter should throw an error
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [state] passed from Wristband during callback');
    }

    req = httpMocks.createRequest({
      query: { code: 'code', state: ['1', '2'] },
    });
    res = httpMocks.createResponse();
    mockReq = req as unknown as NextApiRequest;
    mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Multiple state query parameters should throw an error
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
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

    // Create mock request and response
    let { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', tenant_domain: 'devs4you' },
      cookies: { 'login#state#1234567890': encryptedLoginState },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    let mockReq = req as unknown as NextApiRequest;
    let mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Missing code query parameter should throw an error for happy path scenarios.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }

    req = httpMocks.createRequest({
      query: { state: 'state', code: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    res = httpMocks.createResponse();
    mockReq = req as unknown as NextApiRequest;
    mockRes = res as unknown as MockResponse<NextApiResponse>;
    // Multiple code query parameters should throw an error.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [code] passed from Wristband during callback');
    }
  });

  test('Invalid error query param', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', error: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error] passed from Wristband during callback');
    }
  });

  test('Invalid error_description query param', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', error_description: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Multiple error_description query parameters should throw an error.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('Invalid query parameter [error_description] passed from Wristband during callback');
    }
  });

  test('Invalid tenant_domain query param', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', tenant_domain: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was encountered');
    }
  });

  test('Invalid tenant_custom_domain query param', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', tenant_custom_domain: ['a', 'b'] },
      cookies: { 'login#state#1234567890': 'blah' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Multiple error query parameters should throw an error.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
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

    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${REDIRECT_URI}`,
      query: { state: 'state', tenant_domain: 'devs4you', error: 'BAD', error_description: 'Really bad' },
      cookies: { 'login#state#1234567890': encryptedLoginState },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    // Only some errors are handled automatically by the SDK. All others will throw a WristbandError.
    try {
      await wristbandAuth.pageRouter.callback(mockReq, mockRes);
      expect('').fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof WristbandError).toBe(true);
      expect(error.getError()).toBe('BAD');
      expect(error.getErrorDescription()).toBe('Really bad');
    }
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
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${REDIRECT_URI}`,
        query: { state: 'state', code: 'code' },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      try {
        await wristbandAuth.pageRouter.callback(mockReq, mockRes);
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
      });

      // Create mock request and response
      const { req, res } = createMocks({
        method: 'GET',
        url: `${REDIRECT_URI}`,
        query: { state: 'state', code: 'code' },
        headers: { host: parseTenantFromRootDomain },
      });
      // Cast req and res to NextApiRequest and NextApiResponse
      const mockReq = req as unknown as NextApiRequest;
      const mockRes = res as unknown as MockResponse<NextApiResponse>;

      try {
        await wristbandAuth.pageRouter.callback(mockReq, mockRes);
        expect('').fail('Error expected to be thrown.');
      } catch (error: any) {
        expect(error instanceof WristbandError).toBe(true);
        expect(error.getError()).toBe('missing_tenant_subdomain');
        expect(error.getErrorDescription()).toBe('Callback request URL is missing a tenant subdomain');
      }
    });
  });
});
