import { createMocks } from 'node-mocks-http';
import type { NextApiRequest, NextApiResponse } from 'next';
import type { MockResponse } from 'node-mocks-http';

import { createWristbandAuth, WristbandAuth } from '../../src/index';
import { CLIENT_ID, CLIENT_SECRET, createMockNextRequest, LOGIN_STATE_COOKIE_SECRET } from '../test-utils';
import { expectValidateCalled, expectValidateNotCalled, mockWristbandFetch } from '../helpers/mock-fetch';

const CONFIG_CUSTOM_DOMAIN = 'config.tenant.com';
const PARAM_CUSTOM_DOMAIN = 'param.tenant.com';

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
    wristbandApplicationVanityDomain = 'invotasticb2c-invotastic.dev.wristband.dev';

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
        url: `https://${parseTenantFromRootDomain}/api/auth/logout?${query}`,
        headers: { host: parseTenantFromRootDomain },
      });
      return createMockNextRequest(req);
    }

    describe('logoutConfig.tenantCustomDomain (developer-supplied)', () => {
      test('Does not validate the config value, since it cannot be manipulated by the caller', async () => {
        // The validation endpoint would reject this domain, but the config value is never sent to it.
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const request = createRequest('');
        const response = await wristbandAuth.appRouter.logout(request, { tenantCustomDomain: CONFIG_CUSTOM_DOMAIN });
        const location = response.headers.get('location') as string;

        expectValidateNotCalled();
        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });

      test('Skips validating the query param when the config value outranks it', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request, { tenantCustomDomain: CONFIG_CUSTOM_DOMAIN });
        const location = response.headers.get('location') as string;

        // Validated only when it's needed: a LogoutConfig custom domain outranks it (v5 always validated it)
        expect(global.fetch).not.toHaveBeenCalled();
        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });

      test('Still uses the config value when the query param is invalid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request, { tenantCustomDomain: CONFIG_CUSTOM_DOMAIN });
        const location = response.headers.get('location') as string;

        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });
    });

    describe('Priority 2: logoutConfig.tenantName', () => {
      test('Still uses tenantName when the query param is invalid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request, { tenantName: 'priority2tenant' });
        const location = response.headers.get('location') as string;

        expect(new URL(location).origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
      });

      test('Redirects using tenantName when the query param is valid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request, { tenantName: 'priority2tenant' });
        const location = response.headers.get('location') as string;

        expect(new URL(location).origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
      });
    });

    describe('Priority 3: tenant_custom_domain query param', () => {
      test('Validates the query param and redirects to it when valid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request);
        const location = response.headers.get('location') as string;

        expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
        expect(new URL(location).origin).toEqual(`https://${PARAM_CUSTOM_DOMAIN}`);
      });

      test('Skips an invalid query param and falls through to the tenant name', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}&tenant_name=devs4you`);
        const response = await wristbandAuth.appRouter.logout(request);
        const location = response.headers.get('location') as string;

        expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
        expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      });

      test('Falls back to application-level login when an invalid query param is the only domain', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request);
        const location = response.headers.get('location') as string;

        expect(location).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      });

      test('Skips the query param when the validation endpoint fails', async () => {
        // @wristband/typescript-auth treats a domain it can't validate as unverified and falls through (v5 threw FetchError)
        mockWristbandFetch({ validateStatus: 500 });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        const response = await wristbandAuth.appRouter.logout(request);

        expect(response.headers.get('location')).toEqual(
          `https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`
        );
      });

      test('Revokes the refresh token before validating the query param', async () => {
        const fetchMock = mockWristbandFetch({ tenantCustomDomainValid: true });

        const request = createRequest(`tenant_custom_domain=${PARAM_CUSTOM_DOMAIN}`);
        await wristbandAuth.appRouter.logout(request, { refreshToken: 'refreshToken' });

        expect(fetchMock.mock.calls[0][0]).toContain('/oauth2/revoke');
        expect(fetchMock.mock.calls[1][0]).toContain('/custom-domains/validate');
      });
    });

    describe('Priority 4: tenant name', () => {
      test('Skips validation when no tenant custom domain is present anywhere', async () => {
        mockWristbandFetch();

        const request = createRequest('tenant_name=devs4you');
        const response = await wristbandAuth.appRouter.logout(request);
        const location = response.headers.get('location') as string;

        expectValidateNotCalled();
        expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      });
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

    describe('logoutConfig.tenantCustomDomain (developer-supplied)', () => {
      test('Does not validate the config value, since it cannot be manipulated by the caller', async () => {
        // The validation endpoint would reject this domain, but the config value is never sent to it.
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const { mockReq, mockRes } = createReqRes({});
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes, {
          tenantCustomDomain: CONFIG_CUSTOM_DOMAIN,
        });

        expectValidateNotCalled();
        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });

      test('Skips validating the query param when the config value outranks it', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes, {
          tenantCustomDomain: CONFIG_CUSTOM_DOMAIN,
        });

        // Validated only when it's needed: a LogoutConfig custom domain outranks it (v5 always validated it)
        expect(global.fetch).not.toHaveBeenCalled();
        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });

      test('Still uses the config value when the query param is invalid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes, {
          tenantCustomDomain: CONFIG_CUSTOM_DOMAIN,
        });

        expect(new URL(location).origin).toEqual(`https://${CONFIG_CUSTOM_DOMAIN}`);
      });
    });

    describe('Priority 2: logoutConfig.tenantName', () => {
      test('Still uses tenantName when the query param is invalid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes, { tenantName: 'priority2tenant' });

        expect(new URL(location).origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
      });

      test('Redirects using tenantName when the query param is valid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes, { tenantName: 'priority2tenant' });

        expect(new URL(location).origin).toEqual(`https://priority2tenant-${wristbandApplicationVanityDomain}`);
      });
    });

    describe('Priority 3: tenant_custom_domain query param', () => {
      test('Validates the query param and redirects to it when valid', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: true });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

        expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
        expect(new URL(location).origin).toEqual(`https://${PARAM_CUSTOM_DOMAIN}`);
      });

      test('Skips an invalid query param and falls through to the tenant name', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const { mockReq, mockRes } = createReqRes({
          tenant_custom_domain: PARAM_CUSTOM_DOMAIN,
          tenant_name: 'devs4you',
        });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

        expectValidateCalled(wristbandApplicationVanityDomain, PARAM_CUSTOM_DOMAIN);
        expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      });

      test('Falls back to application-level login when an invalid query param is the only domain', async () => {
        mockWristbandFetch({ tenantCustomDomainValid: false });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

        expect(location).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      });

      test('Skips the query param when the validation endpoint fails', async () => {
        // @wristband/typescript-auth treats a domain it can't validate as unverified and falls through (v5 threw FetchError)
        mockWristbandFetch({ validateStatus: 500 });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

        expect(location).toEqual(`https://${wristbandApplicationVanityDomain}/login?client_id=${CLIENT_ID}`);
      });

      test('Revokes the refresh token before validating the query param', async () => {
        const fetchMock = mockWristbandFetch({ tenantCustomDomainValid: true });

        const { mockReq, mockRes } = createReqRes({ tenant_custom_domain: PARAM_CUSTOM_DOMAIN });
        await wristbandAuth.pagesRouter.logout(mockReq, mockRes, { refreshToken: 'refreshToken' });

        expect(fetchMock.mock.calls[0][0]).toContain('/oauth2/revoke');
        expect(fetchMock.mock.calls[1][0]).toContain('/custom-domains/validate');
      });
    });

    describe('Priority 4: tenant name', () => {
      test('Skips validation when no tenant custom domain is present anywhere', async () => {
        mockWristbandFetch();

        const { mockReq, mockRes } = createReqRes({ tenant_name: 'devs4you' });
        const location = await wristbandAuth.pagesRouter.logout(mockReq, mockRes);

        expectValidateNotCalled();
        expect(new URL(location).origin).toEqual(`https://devs4you-${wristbandApplicationVanityDomain}`);
      });
    });
  });
});
