/* eslint-disable import/no-extraneous-dependencies */

import { createMocks, MockResponse } from 'node-mocks-http';

import { NextApiRequest, NextApiResponse } from 'next';
import { createWristbandAuth, WristbandAuth } from '../../src/index';

const CLIENT_ID = 'clientId';
const CLIENT_SECRET = 'clientSecret';
const LOGIN_STATE_COOKIE_SECRET = '7ffdbecc-ab7d-4134-9307-2dfcc52f7475';
const WRISTBAND_APPLICATION_DOMAIN = 'invotasticb2c-invotastic.dev.wristband.dev';

describe('Login Errors', () => {
  let wristbandAuth: WristbandAuth;

  const loginUrl = 'http://localhost:6001/api/auth/login';
  const redirectUri = 'http://localhost:6001/api/auth/callback';

  beforeEach(() => {
    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain: WRISTBAND_APPLICATION_DOMAIN,
      autoConfigureEnabled: false,
    });
  });

  test('Multiple tenant_domain params', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${loginUrl}`,
      query: { tenant_domain: ['tenant1', 'tenant2'] },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    try {
      await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_domain] query parameter was encountered');
    }
  });

  test('Multiple tenant_custom_domain params', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${loginUrl}`,
      query: { tenant_custom_domain: ['tenant1', 'tenant2'] },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    try {
      await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_custom_domain] query parameter was encountered');
    }
  });

  test('Multiple return_url params', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${loginUrl}`,
      query: { tenant_domain: 'test', return_url: ['url1', 'url2'] },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    try {
      await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [return_url] query parameter was encountered');
    }
  });

  test('Multiple login_hint params', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${loginUrl}`,
      query: { tenant_domain: 'test', login_hint: ['hint1', 'hint2'] },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    try {
      await wristbandAuth.pagesRouter.login(mockReq, mockRes);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [login_hint] query parameter was encountered');
    }
  });

  test('Way too large customState', async () => {
    // Create mock request and response
    const { req, res } = createMocks({
      method: 'GET',
      url: `${loginUrl}`,
      query: { tenant_domain: 'test' },
    });
    // Cast req and res to NextApiRequest and NextApiResponse
    const mockReq = req as unknown as NextApiRequest;
    const mockRes = res as unknown as MockResponse<NextApiResponse>;

    const customState = {
      superLong: '1234567890'.repeat(300),
    };

    try {
      await wristbandAuth.pagesRouter.login(mockReq, mockRes, { customState });
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe(
        'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
      );
    }
  });
});
