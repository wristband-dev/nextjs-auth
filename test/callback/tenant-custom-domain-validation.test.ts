import { createMocks } from 'node-mocks-http';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CallbackResult, LoginState } from '../../src/types';
import { encryptLoginState } from '../../src/utils/crypto';
import { CLIENT_ID, CLIENT_SECRET, createMockNextRequest, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const TENANT_CUSTOM_DOMAIN = 'login.tenant.com';

const MOCK_TOKENS = {
  access_token: 'accessToken',
  id_token: 'idToken',
  refresh_token: 'refreshToken',
  expires_in: 1800,
  token_type: 'bearer',
};

const MOCK_USERINFO = {
  sub: '5q6j4qe2cva3dm3cbdvjoxvuze',
  tnt_id: 'fr2vishnqjdvfbcijxa3a4adhe',
  app_id: 'dy42gabu5jebreq6jajskk2n34',
  idp_name: 'wristband',
  email: 'test@wristband.dev',
};

describe('Callback - Tenant Custom Domain Validation', () => {
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

    wristbandAuth = createWristbandAuth({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      loginStateSecret: LOGIN_STATE_COOKIE_SECRET,
      loginUrl,
      redirectUri,
      wristbandApplicationVanityDomain,
      autoConfigureEnabled: false,
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  async function createLoginStateCookieHeader(): Promise<string> {
    const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state' };
    const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
    return `login#state#1234567890=${encryptedLoginState}`;
  }

  describe('App Router', () => {
    async function createRequest(query: string, withCookie = true) {
      const headers: Record<string, string> = { host: parseTenantFromRootDomain };
      if (withCookie) {
        headers.cookie = await createLoginStateCookieHeader();
      }
      const { req } = createMocks({ method: 'GET', url: `${redirectUri}?${query}`, headers });
      return createMockNextRequest(req);
    }

    test('Validates the tenant_custom_domain query param and completes the callback when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const request = await createRequest(
        `state=state&code=code&tenant_name=devs4you&tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`
      );
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(request);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(callbackResult.type).toBe('completed');
      expect(callbackResult.callbackData?.tenantCustomDomain).toBe(TENANT_CUSTOM_DOMAIN);
    });

    test('Skips an invalid tenant custom domain and omits it from the callback data', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const request = await createRequest(
        `state=state&code=code&tenant_name=devs4you&tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`
      );
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(request);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(callbackResult.type).toBe('completed');
      expect(callbackResult.callbackData?.tenantCustomDomain).toBeUndefined();
    });

    test('Validates before exchanging the authorization code for tokens', async () => {
      const fetchMock = mockWristbandFetch({
        tenantCustomDomainValid: true,
        tokens: MOCK_TOKENS,
        userinfo: MOCK_USERINFO,
      });

      const request = await createRequest(
        `state=state&code=code&tenant_name=devs4you&tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`
      );
      await wristbandAuth.appRouter.callback(request);

      expect(fetchMock.mock.calls[0][0]).toContain('/custom-domains/validate');
      expect(fetchMock.mock.calls[1][0]).toContain('/oauth2/token');
    });

    test('Omits an invalid tenant custom domain from the login redirect URL', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      // No login state cookie forces the redirect_required path.
      const request = await createRequest(
        `state=state&code=code&tenant_name=devs4you&tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`,
        false
      );
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(request);

      expect(callbackResult.type).toBe('redirect_required');
      expect(callbackResult.redirectUrl).not.toContain('tenant_custom_domain');
    });

    test('Skips validation when no tenant_custom_domain query param is present', async () => {
      mockWristbandFetch({ tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const request = await createRequest('state=state&code=code&tenant_name=devs4you');
      const callbackResult: CallbackResult = await wristbandAuth.appRouter.callback(request);

      expectValidateNotCalled();
      expect(callbackResult.type).toBe('completed');
    });
  });

  describe('Pages Router', () => {
    async function createReqRes(query: Record<string, string>, withCookie = true) {
      // The pages router reads the login state from req.cookies rather than a raw cookie header.
      const loginState: LoginState = { codeVerifier: 'codeVerifier', redirectUri, state: 'state' };
      const encryptedLoginState: string = await encryptLoginState(loginState, LOGIN_STATE_COOKIE_SECRET);
      const cookies = withCookie ? { 'login#state#1234567890': encryptedLoginState } : {};
      const { req, res } = createMocks({
        method: 'GET',
        url: redirectUri,
        headers: { host: parseTenantFromRootDomain },
        cookies,
        query,
      });
      return {
        mockReq: req as unknown as NextApiRequest,
        mockRes: res as unknown as MockResponse<NextApiResponse>,
      };
    }

    test('Validates the tenant_custom_domain query param and completes the callback when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const { mockReq, mockRes } = await createReqRes({
        state: 'state',
        code: 'code',
        tenant_name: 'devs4you',
        tenant_custom_domain: TENANT_CUSTOM_DOMAIN,
      });
      const callbackResult: CallbackResult = await wristbandAuth.pagesRouter.callback(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(callbackResult.type).toBe('completed');
      expect(callbackResult.callbackData?.tenantCustomDomain).toBe(TENANT_CUSTOM_DOMAIN);
    });

    test('Skips an invalid tenant custom domain and omits it from the callback data', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const { mockReq, mockRes } = await createReqRes({
        state: 'state',
        code: 'code',
        tenant_name: 'devs4you',
        tenant_custom_domain: TENANT_CUSTOM_DOMAIN,
      });
      const callbackResult: CallbackResult = await wristbandAuth.pagesRouter.callback(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(callbackResult.type).toBe('completed');
      expect(callbackResult.callbackData?.tenantCustomDomain).toBeUndefined();
    });

    test('Omits an invalid tenant custom domain from the login redirect URL', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false, tokens: MOCK_TOKENS, userinfo: MOCK_USERINFO });

      const { mockReq, mockRes } = await createReqRes(
        { state: 'state', code: 'code', tenant_name: 'devs4you', tenant_custom_domain: TENANT_CUSTOM_DOMAIN },
        false
      );
      const callbackResult: CallbackResult = await wristbandAuth.pagesRouter.callback(mockReq, mockRes);

      expect(callbackResult.type).toBe('redirect_required');
      expect(callbackResult.redirectUrl).not.toContain('tenant_custom_domain');
    });
  });
});
