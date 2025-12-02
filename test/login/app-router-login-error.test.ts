/* eslint-disable import/no-extraneous-dependencies */

import { createMocks } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { createMockNextRequest } from '../test-utils';

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

  test('Multiple tenant_name params', async () => {
    // Create mock request
    const { req } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_name=tenant1&tenant_name=tenant2`,
    });
    const mockNextRequest = createMockNextRequest(req);

    try {
      await wristbandAuth.appRouter.login(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_name] query parameter was encountered');
    }
  });

  test('Multiple tenant_custom_domain params', async () => {
    // Create mock request
    const { req } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_custom_domain=tenant1&tenant_custom_domain=tenant2`,
    });
    const mockNextRequest = createMockNextRequest(req);

    try {
      await wristbandAuth.appRouter.login(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [tenant_custom_domain] query parameter was encountered');
    }
  });

  test('Multiple return_url params', async () => {
    // Create mock request
    const { req } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_name=tenant1&return_url=url1&return_url=url2`,
    });
    const mockNextRequest = createMockNextRequest(req);

    try {
      await wristbandAuth.appRouter.login(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [return_url] query parameter was encountered');
    }
  });

  test('Multiple login_hint params', async () => {
    // Create mock request
    const { req } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_name=tenant1&login_hint=hint1&login_hint=hint2`,
    });
    const mockNextRequest = createMockNextRequest(req);

    try {
      await wristbandAuth.appRouter.login(mockNextRequest);
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe('More than one [login_hint] query parameter was encountered');
    }
  });

  test('Way too large customState', async () => {
    // Create mock request
    const { req } = createMocks({
      method: 'GET',
      url: `${loginUrl}?tenant_name=test`,
    });
    const mockNextRequest = createMockNextRequest(req);

    const customState = {
      superLong: '1234567890'.repeat(300),
    };

    try {
      await wristbandAuth.appRouter.login(mockNextRequest, { customState });
      fail('Error expected to be thrown.');
    } catch (error: any) {
      expect(error instanceof TypeError).toBe(true);
      expect(error.message).toBe(
        'Login state cookie exceeds 4kB in size. Ensure your [customState] and [returnUrl] values are a reasonable size.'
      );
    }
  });
});
