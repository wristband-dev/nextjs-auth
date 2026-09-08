import { createMocks } from 'node-mocks-http';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, createMockNextRequest, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const TENANT_CUSTOM_DOMAIN = 'login.tenant.com';

describe('Logout - Tenant Custom Domain Validation', () => {
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

  describe('App Router', () => {
    function createRequest(query: string) {
      const { req } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout?${query}`,
        headers: { host: parseTenantFromRootDomain },
      });
      return createMockNextRequest(req);
    }

    test('Validates the tenant_custom_domain query param and uses it when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const response = await wristbandAuth.appRouter.logout(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`)
      );
      const location = response.headers.get('location') as string;

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(location).origin).toEqual(`https://${TENANT_CUSTOM_DOMAIN}`);
    });

    test('Skips an invalid tenant custom domain and falls through to tenant_name', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const response = await wristbandAuth.appRouter.logout(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}&tenant_name=devs4you`)
      );
      const location = response.headers.get('location') as string;

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });

    test('Does not call the validation endpoint when no tenant custom domain is present', async () => {
      mockWristbandFetch();

      await wristbandAuth.appRouter.logout(createRequest('tenant_name=devs4you'));

      expectValidateNotCalled();
    });
  });

  describe('Pages Router', () => {
    function createReqRes(query: Record<string, string>) {
      const { req, res } = createMocks({
        method: 'GET',
        url: `https://${parseTenantFromRootDomain}/api/auth/logout`,
        headers: { host: parseTenantFromRootDomain },
        query,
      });
      return {
        mockReq: req as unknown as NextApiRequest,
        mockRes: res as unknown as MockResponse<NextApiResponse>,
      };
    }

    test('Validates the tenant_custom_domain query param and uses it when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: TENANT_CUSTOM_DOMAIN });
      const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(location).origin).toEqual(`https://${TENANT_CUSTOM_DOMAIN}`);
    });

    test('Skips an invalid tenant custom domain and falls through to tenant_name', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const { mockReq, mockRes } = createReqRes({
        tenant_custom_domain: TENANT_CUSTOM_DOMAIN,
        tenant_name: 'devs4you',
      });
      const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });
  });
});
