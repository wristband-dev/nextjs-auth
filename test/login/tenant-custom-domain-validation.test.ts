import { createMocks } from 'node-mocks-http';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { FetchError } from '../../src/error';
import { CLIENT_ID, CLIENT_SECRET, createMockNextRequest, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const TENANT_CUSTOM_DOMAIN = 'login.tenant.com';

describe('Login - Tenant Custom Domain Validation', () => {
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
      applicationAuthorizationRequestsEnabled: false,
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('App Router', () => {
    function createRequest(query: string) {
      const { req } = createMocks({
        method: 'GET',
        url: `${loginUrl}?${query}`,
        headers: { host: parseTenantFromRootDomain },
      });
      return createMockNextRequest(req);
    }

    test('Validates the tenant_custom_domain query param and uses it when valid', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: true });

      const response = await wristbandAuth.appRouter.login(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`)
      );
      const authorizeUrl = response.headers.get('location') as string;

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(authorizeUrl).origin).toEqual(`https://${TENANT_CUSTOM_DOMAIN}`);
    });

    test('Skips an invalid tenant custom domain and falls through to tenant_name', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const response = await wristbandAuth.appRouter.login(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}&tenant_name=devs4you`)
      );
      const authorizeUrl = response.headers.get('location') as string;

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(authorizeUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });

    test('Skips an invalid tenant custom domain and falls through to the defaultTenantCustomDomain config', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const response = await wristbandAuth.appRouter.login(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`),
        {
          defaultTenantCustomDomain: 'default.tenant.com',
        }
      );
      const authorizeUrl = response.headers.get('location') as string;

      expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
    });

    test('Redirects to application-level login when an invalid tenant custom domain is the only domain', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const response = await wristbandAuth.appRouter.login(
        createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`)
      );
      const appLoginUrl = response.headers.get('location') as string;

      expect(appLoginUrl).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      expect(response.headers.getSetCookie()).toHaveLength(0);
    });

    test('Does not call the validation endpoint when no tenant custom domain is present', async () => {
      mockWristbandFetch();

      await wristbandAuth.appRouter.login(createRequest('tenant_name=devs4you'));

      expectValidateNotCalled();
    });

    test('Skips validation for the defaultTenantCustomDomain login config', async () => {
      mockWristbandFetch();

      const response = await wristbandAuth.appRouter.login(createRequest(''), {
        defaultTenantCustomDomain: 'default.tenant.com',
      });
      const authorizeUrl = response.headers.get('location') as string;

      expectValidateNotCalled();
      expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
    });

    test('Propagates a FetchError when the validation endpoint fails', async () => {
      mockWristbandFetch({ validateStatus: 500 });

      await expect(
        wristbandAuth.appRouter.login(createRequest(`tenant_custom_domain=${TENANT_CUSTOM_DOMAIN}`))
      ).rejects.toThrow(FetchError);
    });
  });

  describe('Pages Router', () => {
    function createReqRes(query: Record<string, string>) {
      const { req, res } = createMocks({
        method: 'GET',
        url: loginUrl,
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
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(authorizeUrl).origin).toEqual(`https://${TENANT_CUSTOM_DOMAIN}`);
    });

    test('Skips an invalid tenant custom domain and falls through to tenant_name', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const { mockReq, mockRes } = createReqRes({
        tenant_custom_domain: TENANT_CUSTOM_DOMAIN,
        tenant_name: 'devs4you',
      });
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expectValidateCalled(wristbandApplicationVanityDomain, TENANT_CUSTOM_DOMAIN);
      expect(new URL(authorizeUrl).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
    });

    test('Skips an invalid tenant custom domain and falls through to the defaultTenantCustomDomain config', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: TENANT_CUSTOM_DOMAIN });
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'default.tenant.com',
      });

      expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
    });

    test('Redirects to application-level login when an invalid tenant custom domain is the only domain', async () => {
      mockWristbandFetch({ tenantCustomDomainValid: false });

      const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: TENANT_CUSTOM_DOMAIN });
      const appLoginUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expect(appLoginUrl).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      expect(mockRes.getHeader('Set-Cookie')).toBeUndefined();
    });

    test('Does not call the validation endpoint when no tenant custom domain is present', async () => {
      mockWristbandFetch();

      const { mockReq, mockRes } = createReqRes({ tenant_name: 'devs4you' });
      await wristbandAuth.pagesRouter.login(mockReq, mockRes);

      expectValidateNotCalled();
    });

    test('Skips validation for the defaultTenantCustomDomain login config', async () => {
      mockWristbandFetch();

      const { mockReq, mockRes } = createReqRes({});
      const authorizeUrl = await wristbandAuth.pagesRouter.login(mockReq, mockRes, {
        defaultTenantCustomDomain: 'default.tenant.com',
      });

      expectValidateNotCalled();
      expect(new URL(authorizeUrl).origin).toEqual('https://default.tenant.com');
    });

    test('Propagates a FetchError when the validation endpoint fails', async () => {
      mockWristbandFetch({ validateStatus: 500 });

      const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: TENANT_CUSTOM_DOMAIN });
      await expect(wristbandAuth.pagesRouter.login(mockReq, mockRes)).rejects.toThrow(FetchError);
    });
  });
});
